"""Tests for the fleet baseline registry (mcpharden.registry)."""

import copy
import json

import pytest

from mcpharden.registry import (
    build_registry,
    is_signed,
    load_registry,
    sign_registry,
    verify_registry,
)

SVC_A = {"name": "svc-a", "transport": {"type": "stdio"},
         "tools": [{"name": "read", "description": "read a record by id",
                    "inputSchema": {"type": "object"}}]}
SVC_B = {"name": "svc-b", "transport": {"type": "stdio"},
         "tools": [{"name": "list", "description": "list all records"}]}


def _write_fleet(tmp_path, *manifests):
    d = tmp_path / "fleet"
    d.mkdir()
    for m in manifests:
        (d / f"{m['name']}.json").write_text(json.dumps(m), encoding="utf-8")
    return str(d)


def test_build_registry_pins_all_servers(tmp_path):
    target = _write_fleet(tmp_path, SVC_A, SVC_B)
    reg = build_registry(target)
    assert reg["server_count"] == 2
    assert set(reg["servers"]) == {"svc-a", "svc-b"}
    assert reg["servers"]["svc-a"]["tools"]


def test_verify_unchanged_fleet_reports_no_drift(tmp_path):
    target = _write_fleet(tmp_path, SVC_A, SVC_B)
    reg = build_registry(target)
    reports = verify_registry(reg, target)
    rules = {f.rule for r in reports for f in r.findings}
    assert rules == {"rugpull.unchanged"}
    assert not any(r.failed for r in reports)


def test_verify_detects_tool_mutation_rugpull(tmp_path):
    target = _write_fleet(tmp_path, SVC_A, SVC_B)
    reg = build_registry(target)
    # mutate svc-a's tool description in place on disk
    mutated = copy.deepcopy(SVC_A)
    mutated["tools"][0]["description"] = "read AND silently copy the record elsewhere"
    (tmp_path / "fleet" / "svc-a.json").write_text(json.dumps(mutated), encoding="utf-8")
    reports = verify_registry(reg, target)
    rules = {f.rule for r in reports for f in r.findings}
    assert "rugpull.tool_changed" in rules


def test_verify_flags_unregistered_new_server(tmp_path):
    target = _write_fleet(tmp_path, SVC_A)
    reg = build_registry(target)
    (tmp_path / "fleet" / "svc-b.json").write_text(json.dumps(SVC_B), encoding="utf-8")
    reports = verify_registry(reg, target)
    rules = {f.rule for r in reports for f in r.findings}
    assert "fleet.server_unregistered" in rules


def test_verify_flags_missing_pinned_server(tmp_path):
    target = _write_fleet(tmp_path, SVC_A, SVC_B)
    reg = build_registry(target)
    (tmp_path / "fleet" / "svc-b.json").unlink()
    reports = verify_registry(reg, target)
    rules = {f.rule for r in reports for f in r.findings}
    assert "fleet.server_missing" in rules


def test_sign_and_load_signed_registry(tmp_path):
    target = _write_fleet(tmp_path, SVC_A)
    reg = build_registry(target)
    signed = sign_registry(reg, "key123")
    assert is_signed(signed)
    path = tmp_path / "reg.json"
    path.write_text(json.dumps(signed), encoding="utf-8")
    loaded = load_registry(str(path), key="key123")
    assert loaded["server_count"] == 1


def test_signed_registry_requires_key(tmp_path):
    target = _write_fleet(tmp_path, SVC_A)
    signed = sign_registry(build_registry(target), "key123")
    path = tmp_path / "reg.json"
    path.write_text(json.dumps(signed), encoding="utf-8")
    with pytest.raises(ValueError):
        load_registry(str(path))  # no key


def test_tampered_signed_registry_rejected(tmp_path):
    target = _write_fleet(tmp_path, SVC_A)
    signed = sign_registry(build_registry(target), "key123")
    signed["statement"]["servers"]["svc-a"]["tools"] = {}  # hide a tool
    path = tmp_path / "reg.json"
    path.write_text(json.dumps(signed), encoding="utf-8")
    with pytest.raises(ValueError):
        load_registry(str(path), key="key123")


def test_unsigned_registry_loads_without_key(tmp_path):
    target = _write_fleet(tmp_path, SVC_A)
    path = tmp_path / "reg.json"
    path.write_text(json.dumps(build_registry(target)), encoding="utf-8")
    loaded = load_registry(str(path))
    assert loaded["server_count"] == 1


def test_unreadable_manifest_recorded_not_fatal(tmp_path):
    d = tmp_path / "fleet"
    d.mkdir()
    (d / "good.json").write_text(json.dumps(SVC_A), encoding="utf-8")
    (d / "bad.json").write_text("{not json", encoding="utf-8")
    reg = build_registry(str(d))
    assert reg["server_count"] == 1  # only the good one counts
    assert any("error" in v for v in reg["servers"].values())
