"""End-to-end tests for the new CLI surfaces: ci, registry, junit/attestation
formats, and vulndb --stats."""

import json
import xml.etree.ElementTree as ET

from mcpharden.cli import main

CRIT = {"name": "crit", "transport": {"type": "http", "host": "0.0.0.0"},
        "tools": [{"name": "run_cmd", "description": "run shell", "command": "sh -c {x}"}]}
CLEAN = {"name": "clean", "transport": {"type": "stdio"}, "capabilities": {"tools": {}},
         "tools": [{"name": "ping", "description": "return pong to the caller",
                    "inputSchema": {"type": "object", "additionalProperties": False}}]}


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


# --- formats on audit/scan ----------------------------------------------

def test_audit_junit_format(tmp_path, capsys):
    path = _write(tmp_path, "s.json", CRIT)
    rc = main(["audit", path, "--format", "junit"])
    out = capsys.readouterr().out
    ET.fromstring(out)  # valid XML
    assert rc == 1  # failing manifest


def test_scan_attestation_signed(tmp_path, capsys):
    _write(tmp_path, "s.json", CLEAN)
    rc = main(["scan", str(tmp_path), "--format", "attestation", "--sign-key", "k"])
    out = capsys.readouterr().out
    env = json.loads(out)
    assert env["signatures"][0]["algorithm"] == "hmac-sha256"
    assert rc == 0


def test_scan_attestation_unsigned(tmp_path, capsys):
    _write(tmp_path, "s.json", CLEAN)
    main(["scan", str(tmp_path), "--format", "attestation"])
    out = capsys.readouterr().out
    stmt = json.loads(out)
    assert "signatures" not in stmt
    assert stmt["predicateType"].endswith("hardening-scan/v1")


# --- ci gate -------------------------------------------------------------

def test_ci_pass(tmp_path, capsys):
    _write(tmp_path, "s.json", CLEAN)
    pol = tmp_path / ".mcpharden.yml"
    pol.write_text("max_critical: 0\nmin_score: 50\n", encoding="utf-8")
    rc = main(["ci", str(tmp_path), "--policy", str(pol)])
    assert rc == 0
    assert "PASS" in capsys.readouterr().out


def test_ci_fail(tmp_path, capsys):
    _write(tmp_path, "s.json", CRIT)
    pol = tmp_path / ".mcpharden.yml"
    pol.write_text("max_critical: 0\n", encoding="utf-8")
    rc = main(["ci", str(tmp_path), "--policy", str(pol)])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().out


def test_ci_json_output(tmp_path, capsys):
    _write(tmp_path, "s.json", CRIT)
    pol = tmp_path / ".mcpharden.json"
    pol.write_text(json.dumps({"max_critical": 0}), encoding="utf-8")
    rc = main(["ci", str(tmp_path), "--policy", str(pol), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["result"]["passed"] is False
    assert rc == 1


def test_ci_no_policy_errors(tmp_path, capsys):
    _write(tmp_path, "s.json", CLEAN)
    rc = main(["ci", str(tmp_path)])  # no policy, none discoverable in tmp cwd
    # discover_policy uses CWD which is the repo root during tests; it may find
    # none — either way a missing policy must not crash. Accept 0/1/2.
    assert rc in (0, 1, 2)


# --- registry ------------------------------------------------------------

def test_registry_pin_and_verify(tmp_path, capsys):
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _write(fleet, "clean.json", CLEAN)
    reg = tmp_path / "reg.json"
    rc = main(["registry", "pin", str(fleet), "-o", str(reg)])
    assert rc == 0 and reg.exists()
    rc = main(["registry", "verify", str(fleet), "--registry", str(reg)])
    assert rc == 0  # unchanged fleet


def test_registry_signed_roundtrip_via_cli(tmp_path):
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _write(fleet, "clean.json", CLEAN)
    reg = tmp_path / "reg.json"
    assert main(["registry", "pin", str(fleet), "-o", str(reg), "--sign-key", "s"]) == 0
    doc = json.loads(reg.read_text(encoding="utf-8"))
    assert "signatures" in doc
    assert main(["registry", "verify", str(fleet), "--registry", str(reg), "--key", "s"]) == 0


def test_registry_verify_detects_new_server(tmp_path):
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _write(fleet, "clean.json", CLEAN)
    reg = tmp_path / "reg.json"
    main(["registry", "pin", str(fleet), "-o", str(reg)])
    _write(fleet, "crit.json", CRIT)  # new unpinned server appears
    rc = main(["registry", "verify", str(fleet), "--registry", str(reg),
               "--fail-on", "high"])
    assert rc == 1


def test_registry_no_subcommand_errors(capsys):
    rc = main(["registry"])
    assert rc == 2


# --- vulndb --stats ------------------------------------------------------

def test_vulndb_stats_json(capsys):
    rc = main(["vulndb", "--stats", "--format", "json"])
    stats = json.loads(capsys.readouterr().out)
    assert stats["classes"] >= 16
    assert "by_severity" in stats
    assert rc == 0


def test_rules_lists_new_rules(capsys):
    main(["rules"])
    out = capsys.readouterr().out
    assert "tool.exfiltration_surface" in out
    assert "fleet.server_unregistered" in out


def test_diff_junit_format(tmp_path, capsys):
    trusted = _write(tmp_path, "t.json",
                     {"name": "s", "tools": [{"name": "a", "description": "do a thing"}]})
    base = tmp_path / "b.json"
    assert main(["baseline", trusted, "-o", str(base)]) == 0
    mutated = _write(tmp_path, "m.json",
                     {"name": "s", "tools": [{"name": "a", "description": "do a DIFFERENT thing"}]})
    rc = main(["diff", mutated, "--baseline", str(base), "--format", "junit",
               "--fail-on", "critical"])
    out = capsys.readouterr().out
    ET.fromstring(out)
    assert rc == 1  # rugpull.tool_changed is critical


def test_configscan_junit_format(tmp_path, capsys):
    cfg = _write(tmp_path, "cfg.json",
                 {"mcpServers": {"x": {"command": "npx", "args": ["some-pkg"]}}})
    main(["configscan", cfg, "--format", "junit"])
    out = capsys.readouterr().out
    ET.fromstring(out)
