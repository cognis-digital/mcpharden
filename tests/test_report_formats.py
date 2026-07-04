"""Tests for the JUnit + signed-attestation exporters (mcpharden.report)."""

import json
import xml.etree.ElementTree as ET

import pytest

from mcpharden import audit_manifest, scan
from mcpharden.report import (
    build_attestation,
    sign_attestation,
    to_attestation_json,
    to_junit,
    verify_attestation,
)

FAILING = {
    "name": "risky",
    "transport": {"type": "http", "host": "0.0.0.0"},
    "tools": [{"name": "run_cmd", "description": "run a shell command",
               "command": "sh -c {{input}}"}],
}
CLEAN = {
    "name": "safe",
    "transport": {"type": "stdio"},
    "capabilities": {"tools": {}},
    "tools": [{"name": "ping", "description": "return pong to the caller",
               "inputSchema": {"type": "object", "additionalProperties": False}}],
}


def _reports(*manifests):
    return [audit_manifest(m, source=m["name"] + ".json") for m in manifests]


# --- JUnit ---------------------------------------------------------------

def test_junit_is_well_formed_xml():
    xml = to_junit(_reports(FAILING, CLEAN))
    root = ET.fromstring(xml)  # raises if malformed
    assert root.tag == "testsuites"
    suite = root.find("testsuite")
    assert suite.get("tests") == "2"


def test_junit_failing_server_has_failure_element():
    xml = to_junit(_reports(FAILING))
    root = ET.fromstring(xml)
    case = root.find(".//testcase")
    assert case.find("failure") is not None


def test_junit_clean_server_has_no_failure():
    xml = to_junit(_reports(CLEAN))
    root = ET.fromstring(xml)
    case = root.find(".//testcase")
    assert case.find("failure") is None
    assert root.find("testsuite").get("failures") == "0"


def test_junit_fail_on_medium_flips_a_clean_pass_to_failure():
    # CLEAN has an info-level capability finding? No — it passes with 0 findings
    # of medium+. Use a manifest that only has a medium finding.
    medium_only = {"name": "m", "transport": {"type": "stdio"},
                   "tools": [{"name": "x"}]}  # tool.no_description = medium
    passing = to_junit(_reports(medium_only), fail_on=None)
    strict = to_junit(_reports(medium_only), fail_on="medium")
    assert ET.fromstring(passing).find("testsuite").get("failures") == "0"
    assert ET.fromstring(strict).find("testsuite").get("failures") == "1"


def test_junit_escapes_xml_special_chars():
    m = {"name": "a<b>&\"c", "transport": {"type": "stdio"}, "tools": []}
    xml = to_junit(_reports(m))
    root = ET.fromstring(xml)  # would raise if raw < & " leaked in
    assert root is not None


def test_junit_empty_reports():
    xml = to_junit([])
    root = ET.fromstring(xml)
    assert root.find("testsuite").get("tests") == "0"


# --- Attestation ---------------------------------------------------------

def test_attestation_statement_shape():
    stmt = build_attestation(_reports(CLEAN))
    assert stmt["predicateType"].endswith("hardening-scan/v1")
    assert stmt["subject"][0]["digest"]["sha256"]
    assert stmt["predicate"]["passed"] is True


def test_attestation_is_deterministic_without_timestamp():
    a = to_attestation_json(_reports(CLEAN))
    b = to_attestation_json(_reports(CLEAN))
    assert a == b


def test_attestation_produced_at_included_when_given():
    stmt = build_attestation(_reports(CLEAN), produced_at="2026-07-01T00:00:00Z")
    assert stmt["predicate"]["producedAt"] == "2026-07-01T00:00:00Z"


def test_sign_and_verify_roundtrip():
    stmt = build_attestation(_reports(FAILING))
    env = sign_attestation(stmt, "hunter2")
    assert verify_attestation(env, "hunter2") is True
    assert verify_attestation(env, "wrong-key") is False


def test_verify_detects_tampering():
    env = json.loads(to_attestation_json(_reports(FAILING), key="k"))
    env["statement"]["predicate"]["servers_failed"] = 0  # lie about the outcome
    assert verify_attestation(env, "k") is False


def test_sign_requires_key():
    with pytest.raises(ValueError):
        sign_attestation(build_attestation(_reports(CLEAN)), "")


def test_verify_is_safe_on_garbage():
    assert verify_attestation({}, "k") is False
    assert verify_attestation({"statement": 1, "signatures": 2}, "k") is False
    assert verify_attestation("not a dict", "k") is False


def test_keyid_is_stable_and_not_the_secret():
    e1 = sign_attestation(build_attestation(_reports(CLEAN)), "sekret")
    e2 = sign_attestation(build_attestation(_reports(CLEAN)), "sekret")
    kid = e1["signatures"][0]["keyid"]
    assert kid == e2["signatures"][0]["keyid"]
    assert "sekret" not in kid


def test_attestation_subject_digest_changes_with_findings():
    a = build_attestation(_reports(CLEAN))["subject"][0]["digest"]["sha256"]
    b = build_attestation(_reports(FAILING))["subject"][0]["digest"]["sha256"]
    assert a != b


def test_attestation_over_directory_scan(tmp_path):
    (tmp_path / "s.json").write_text(json.dumps(CLEAN), encoding="utf-8")
    reports = scan(str(tmp_path))
    env = json.loads(to_attestation_json(reports, key="k"))
    assert verify_attestation(env, "k")
