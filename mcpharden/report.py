"""Additional exporters for mcpharden scan reports.

Adds two report formats on top of the core ``table``/``json``/``sarif``/``html``
serializers:

* **JUnit XML** — every audited server becomes a ``<testcase>``; a failing
  server (or any finding at/above a chosen severity) becomes a ``<failure>``.
  This is the format Jenkins, GitLab CI, CircleCI, Azure Pipelines and the
  ``mikepenz/action-junit-report`` GitHub action already know how to render, so
  a hardening scan shows up next to the unit tests in the CI run summary.

* **Signed attestation** — a deterministic, in-toto-style JSON statement over
  the scan result, signed offline with an HMAC-SHA256 keyed digest. It lets a
  fleet operator *prove* which manifests were scanned, by which tool version,
  with what outcome, and detect tampering after the fact. No network, no
  asymmetric-key management: the key is a shared secret the verifier also holds.

Everything is standard-library only and deterministic (stable ordering, no
timestamps inside the signed payload unless you pass one), so output is
reproducible and diffable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape, quoteattr

from .core import Report, SEVERITY_ORDER, TOOL_NAME, TOOL_VERSION

# Characters XML 1.0 forbids even when entity-escaped (everything below 0x20
# except tab/newline/CR, plus DEL). A manifest under audit for *line-jumping*
# can carry these in a tool name/description, which would land in the JUnit
# output and make it non-well-formed — so strip them to a visible marker.
_XML_ILLEGAL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _xml_clean(s: str) -> str:
    return _XML_ILLEGAL_RE.sub("�", str(s))

__all__ = [
    "to_junit",
    "build_attestation",
    "sign_attestation",
    "verify_attestation",
    "to_attestation_json",
]


# --------------------------------------------------------------------------
# JUnit XML
# --------------------------------------------------------------------------

def _server_failed_at(report: Report, fail_on: Optional[str]) -> bool:
    if not fail_on:
        return report.failed
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER.get(f.severity, 99) <= threshold for f in report.findings)


def to_junit(reports: List[Report], fail_on: Optional[str] = None,
             suite_name: str = "mcpharden") -> str:
    """Render scan reports as a JUnit XML test report.

    One ``<testcase>`` per server. A server that fails the gate emits a
    ``<failure>`` whose body lists its findings; otherwise it passes. The
    ``<system-out>`` always carries the full finding list for context, even on
    passing servers.
    """
    cases: List[str] = []
    total_failures = 0
    for report in reports:
        failed = _server_failed_at(report, fail_on)
        if failed:
            total_failures += 1
        classname = _xml_clean(str(report.source))
        casename = quoteattr(_xml_clean(report.server_name or "unknown"))
        lines = [
            f"[{f.severity.upper()}] {f.rule}: {f.message}"
            + (f" (at {f.location})" if f.location else "")
            for f in report.findings
        ]
        sysout = escape(_xml_clean("\n".join(lines) or "no findings"))
        body = [f'  <testcase classname={quoteattr(classname)} name={casename} '
                f'time="0">']
        if failed:
            c = report.counts
            msg = quoteattr(
                f"score={report.score}/100 critical={c['critical']} "
                f"high={c['high']} medium={c['medium']}")
            body.append(f'    <failure message={msg} type="hardening">'
                        f'{sysout}</failure>')
        body.append(f'    <system-out>{sysout}</system-out>')
        body.append('  </testcase>')
        cases.append("\n".join(body))

    tests = len(reports)
    xml = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name={quoteattr(suite_name)} tests="{tests}" '
        f'failures="{total_failures}">',
        f'  <testsuite name={quoteattr(suite_name)} tests="{tests}" '
        f'failures="{total_failures}" '
        f'package="{escape(TOOL_NAME)}-{escape(TOOL_VERSION)}">',
        *cases,
        '  </testsuite>',
        '</testsuites>',
    ]
    return "\n".join(xml) + "\n"


# --------------------------------------------------------------------------
# Signed attestation (in-toto-style statement, HMAC-signed)
# --------------------------------------------------------------------------

_PREDICATE_TYPE = "https://cognis.digital/mcpharden/hardening-scan/v1"
_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def _subject(report: Report) -> Dict[str, Any]:
    """One in-toto subject per scanned manifest: name + a content digest.

    The digest is a sha256 over the *finding set* (rule+severity+location), so
    the attestation is bound to the exact hardening outcome, not just the file
    path — re-running against a mutated manifest yields a different digest.
    """
    basis = json.dumps(
        {"server": report.server_name,
         "findings": sorted((f.rule, f.severity, f.location) for f in report.findings)},
        sort_keys=True, separators=(",", ":"))
    return {
        "name": report.source,
        "digest": {"sha256": hashlib.sha256(basis.encode("utf-8")).hexdigest()},
    }


def build_attestation(reports: List[Report],
                      produced_at: Optional[str] = None) -> Dict[str, Any]:
    """Build the unsigned in-toto statement for a set of scan reports.

    ``produced_at`` is optional and, when omitted, is left out entirely so the
    payload is fully deterministic (identical inputs → identical bytes → same
    signature). Pass an ISO-8601 string only if you want a timestamp inside the
    signed envelope.
    """
    agg = {k: 0 for k in SEVERITY_ORDER}
    for r in reports:
        for sev, n in r.counts.items():
            agg[sev] += n
    predicate: Dict[str, Any] = {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "servers_scanned": len(reports),
        "servers_failed": sum(1 for r in reports if r.failed),
        "total_findings": sum(len(r.findings) for r in reports),
        "counts": agg,
        "passed": not any(r.failed for r in reports),
        "reports": [r.to_dict() for r in reports],
    }
    if produced_at:
        predicate["producedAt"] = produced_at
    return {
        "_type": _STATEMENT_TYPE,
        "predicateType": _PREDICATE_TYPE,
        "subject": [_subject(r) for r in reports],
        "predicate": predicate,
    }


def _canonical(statement: Dict[str, Any]) -> bytes:
    """Deterministic canonical bytes of a statement for signing/verification."""
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_attestation(statement: Dict[str, Any], key: str) -> Dict[str, Any]:
    """Wrap an unsigned statement in a signed envelope.

    Uses HMAC-SHA256 over the canonical bytes of the statement with ``key`` as
    the shared secret. The returned envelope carries the statement plus a
    signature block; :func:`verify_attestation` recomputes and compares.
    """
    if not key:
        raise ValueError("a non-empty signing key is required")
    payload = _canonical(statement)
    sig = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return {
        "payloadType": "application/vnd.mcpharden.attestation+json",
        "statement": statement,
        "signatures": [{"algorithm": "hmac-sha256", "keyid": _keyid(key), "sig": sig}],
    }


def _keyid(key: str) -> str:
    """A non-reversible short id for a key, so an envelope names which key
    signed it without ever embedding the secret."""
    return hashlib.sha256(("mcpharden-keyid:" + key).encode("utf-8")).hexdigest()[:16]


def verify_attestation(envelope: Dict[str, Any], key: str) -> bool:
    """Return True iff ``envelope`` carries a valid signature under ``key``.

    Constant-time comparison; tolerant of a malformed envelope (returns False
    rather than raising) so it is safe to call on untrusted input.
    """
    if not isinstance(envelope, dict) or not key:
        return False
    statement = envelope.get("statement")
    sigs = envelope.get("signatures")
    if not isinstance(statement, dict) or not isinstance(sigs, list):
        return False
    expected = hmac.new(key.encode("utf-8"), _canonical(statement),
                        hashlib.sha256).hexdigest()
    for s in sigs:
        if isinstance(s, dict) and hmac.compare_digest(str(s.get("sig", "")), expected):
            return True
    return False


def to_attestation_json(reports: List[Report], key: Optional[str] = None,
                        produced_at: Optional[str] = None, indent: int = 2) -> str:
    """Serialize an attestation for a scan.

    With a ``key`` the output is a signed envelope; without one it is the bare
    unsigned statement (useful for inspection / diffing).
    """
    statement = build_attestation(reports, produced_at=produced_at)
    obj: Dict[str, Any] = sign_attestation(statement, key) if key else statement
    return json.dumps(obj, indent=indent, sort_keys=True)
