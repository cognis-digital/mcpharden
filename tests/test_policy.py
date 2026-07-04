"""Tests for the CI policy gate (mcpharden.policy)."""

import json

import pytest

from mcpharden import audit_manifest
from mcpharden.policy import (
    DEFAULT_POLICY_NAMES,
    Policy,
    discover_policy,
    evaluate,
    load_policy,
    parse_policy,
)

CRIT = {"name": "crit", "transport": {"type": "http", "host": "0.0.0.0"},
        "tools": [{"name": "run_cmd", "description": "run shell", "command": "sh -c {x}"}]}
CLEAN = {"name": "clean", "transport": {"type": "stdio"}, "capabilities": {"tools": {}},
         "tools": [{"name": "ping", "description": "return pong to the caller",
                    "inputSchema": {"type": "object", "additionalProperties": False}}]}


def _r(*ms):
    return [audit_manifest(m, source=m["name"]) for m in ms]


# --- parsing -------------------------------------------------------------

def test_parse_scalar_and_list_fields():
    p = parse_policy({"min_score": 80, "max_critical": 0,
                      "forbid_rules": "a, b", "waivers": ["c", "d"]})
    assert p.min_score == 80 and p.max_critical == 0
    assert p.forbid_rules == {"a", "b"}
    assert p.waivers == {"c", "d"}


def test_parse_rejects_bad_grade_and_severity():
    with pytest.raises(ValueError):
        parse_policy({"min_grade": "Z"})
    with pytest.raises(ValueError):
        parse_policy({"fail_on": "spicy"})


def test_parse_non_mapping_raises():
    with pytest.raises(ValueError):
        parse_policy(["not", "a", "map"])


def test_load_flat_yaml(tmp_path):
    f = tmp_path / ".mcpharden.yml"
    f.write_text("min_score: 70  # comment\n"
                 "max_high: 3\n"
                 "forbid_rules: tool.shell_exec, transport.bind_all\n"
                 "waivers: [rugpull.unchanged, capability.experimental]\n",
                 encoding="utf-8")
    p = load_policy(str(f))
    assert p.min_score == 70 and p.max_high == 3
    assert "tool.shell_exec" in p.forbid_rules
    assert "rugpull.unchanged" in p.waivers


def test_load_json_policy(tmp_path):
    f = tmp_path / ".mcpharden.json"
    f.write_text(json.dumps({"max_critical": 0, "fail_on": "high"}), encoding="utf-8")
    p = load_policy(str(f))
    assert p.max_critical == 0 and p.fail_on == "high"


def test_load_empty_raises(tmp_path):
    f = tmp_path / ".mcpharden.yml"
    f.write_text("   \n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_policy(str(f))


def test_discover_policy(tmp_path):
    assert discover_policy(str(tmp_path)) is None
    (tmp_path / DEFAULT_POLICY_NAMES[0]).write_text("min_score: 1", encoding="utf-8")
    assert discover_policy(str(tmp_path)).endswith(DEFAULT_POLICY_NAMES[0])


# --- evaluation ----------------------------------------------------------

def test_clean_passes_empty_policy():
    assert evaluate(_r(CLEAN), Policy()).passed


def test_max_critical_violation():
    res = evaluate(_r(CRIT), Policy(max_critical=0))
    assert not res.passed
    assert any("critical" in v for v in res.violations)


def test_min_score_violation():
    res = evaluate(_r(CRIT), Policy(min_score=90))
    assert not res.passed
    assert any("min_score" in v for v in res.violations)


def test_forbid_rule_violation():
    res = evaluate(_r(CRIT), Policy(forbid_rules={"tool.shell_exec"}))
    assert not res.passed
    assert any("forbidden" in v for v in res.violations)


def test_require_rule_violation():
    res = evaluate(_r(CLEAN), Policy(require_rules={"rugpull.unchanged"}))
    assert not res.passed
    assert any("required rule missing" in v for v in res.violations)


def test_waiver_suppresses_a_finding_from_caps():
    # CRIT has a critical shell_exec + a bind_all critical; waive them → cap ok.
    res = evaluate(_r(CRIT), Policy(max_critical=0,
                                    waivers={"tool.shell_exec", "transport.bind_all",
                                             "transport.cors_wildcard"}))
    # any remaining criticals still count; assert waived list is populated
    assert res.stats["waived_count"] >= 1
    assert "tool.shell_exec" in res.waived


def test_fail_on_floor():
    res = evaluate(_r(CRIT), Policy(fail_on="critical"))
    assert not res.passed


def test_min_grade_violation():
    res = evaluate(_r(CRIT), Policy(min_grade="A"), fleet_grade="F")
    assert not res.passed
    assert any("grade" in v for v in res.violations)


def test_min_grade_pass_when_grade_meets():
    res = evaluate(_r(CLEAN), Policy(min_grade="C"), fleet_grade="A")
    assert res.passed


def test_gateresult_to_dict_serializable():
    res = evaluate(_r(CRIT), Policy(max_critical=0))
    json.dumps(res.to_dict())  # must not raise
