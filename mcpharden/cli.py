"""Command-line interface for MCPHARDEN."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    ManifestError,
    Report,
    SEVERITY_ORDER,
    audit_manifest,
    load_manifest,
    scan,
    scan_to_dict,
    to_html,
    to_sarif,
)

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _render_table(report: Report) -> str:
    lines: List[str] = []
    lines.append(f"MCPHARDEN audit — {report.server_name}  (source: {report.source})")
    lines.append("=" * 68)
    if not report.findings:
        lines.append("No findings. Manifest passes hardening checks.")
    else:
        for f in report.findings:
            label = _SEV_LABEL.get(f.severity, f.severity.upper())
            lines.append(f"[{label}] {f.rule}")
            lines.append(f"        {f.message}")
            if f.location:
                lines.append(f"        at: {f.location}")
            if f.remediation:
                lines.append(f"        fix: {f.remediation}")
    c = report.counts
    lines.append("-" * 68)
    lines.append(
        f"score={report.score}/100  "
        f"critical={c['critical']} high={c['high']} medium={c['medium']} "
        f"low={c['low']} info={c['info']}"
    )
    lines.append("RESULT: " + ("FAIL" if report.failed else "PASS"))
    return "\n".join(lines)


def _render_scan_table(reports: List[Report]) -> str:
    if not reports:
        return "No manifests found to scan."
    blocks = [_render_table(r) for r in reports]
    failing = sum(1 for r in reports if r.failed)
    blocks.append("=" * 68)
    blocks.append(
        f"SCAN SUMMARY: {len(reports)} server(s), {failing} failing, "
        f"{sum(len(r.findings) for r in reports)} finding(s)."
    )
    return "\n\n".join(blocks)


def _fails_gate(reports: List[Report], fail_on: Optional[str]) -> bool:
    """A scan/audit "fails" if any finding is at or above the gate severity.

    With no ``--fail-on`` the default policy is the historical one: any
    critical or high finding fails (``Report.failed``).
    """
    if not fail_on:
        return any(r.failed for r in reports)
    threshold = SEVERITY_ORDER[fail_on]
    return any(
        SEVERITY_ORDER.get(f.severity, 99) <= threshold
        for r in reports for f in r.findings
    )


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="MCP server hardening linter — audits capability "
                    "declarations, transport, and tool descriptions.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    # audit: single manifest, human-first (kept for back-compat).
    audit = sub.add_parser(
        "audit", help="Audit a single MCP server manifest (JSON) for weaknesses.")
    audit.add_argument("manifest", help="Path to the MCP server manifest JSON.")
    audit.add_argument("--format", choices=("table", "json", "sarif", "html"),
                       default="table", help="Output format (default: table).")
    audit.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER),
                       default="info",
                       help="Only report findings at or above this severity.")
    audit.add_argument("--out", help="Write output to this file instead of stdout.")
    audit.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None,
                       help="Exit non-zero if a finding at/above this severity exists.")

    # scan: file OR directory (fleet), all formats.
    sc = sub.add_parser(
        "scan", help="Scan a manifest file or a directory of manifests.")
    sc.add_argument("target", help="Manifest file or directory to scan.")
    sc.add_argument("--format", choices=("table", "json", "sarif", "html"),
                    default="table", help="Output format (default: table).")
    sc.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER), default="info",
                    help="Only report findings at or above this severity.")
    sc.add_argument("--out", help="Write output to this file instead of stdout.")
    sc.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None,
                    help="Exit non-zero if a finding at/above this severity exists.")

    # mcp: expose as an MCP server over stdio.
    mcp = sub.add_parser("mcp", help="Run as an MCP server (stdio JSON-RPC).")
    mcp.add_argument("--host", default=None, help="Reserved; stdio transport only.")

    # rules: list the detection catalogue.
    sub.add_parser("rules", help="List the built-in detection rules.")
    return p


def _apply_min_severity(report: Report, min_sev: str) -> None:
    threshold = SEVERITY_ORDER[min_sev]
    report.findings = [
        f for f in report.findings
        if SEVERITY_ORDER.get(f.severity, 99) <= threshold
    ]


def _run_audit(args: argparse.Namespace) -> int:
    try:
        manifest = load_manifest(args.manifest)
    except (OSError, ManifestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = audit_manifest(manifest, source=args.manifest)
    _apply_min_severity(report, args.min_severity)

    fmt = args.format
    if fmt == "json":
        _emit(json.dumps(report.to_dict(), indent=2), args.out)
    elif fmt == "sarif":
        _emit(json.dumps(to_sarif([report]), indent=2), args.out)
    elif fmt == "html":
        _emit(to_html([report]), args.out)
    else:
        _emit(_render_table(report), args.out)

    return 1 if _fails_gate([report], args.fail_on) else 0


def _run_scan(args: argparse.Namespace) -> int:
    try:
        reports = scan(args.target)
    except (OSError, ManifestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for r in reports:
        _apply_min_severity(r, args.min_severity)

    fmt = args.format
    if fmt == "json":
        # Recompute aggregate from the (possibly severity-filtered) reports.
        payload = scan_to_dict(args.target)
        payload["reports"] = [r.to_dict() for r in reports]
        _emit(json.dumps(payload, indent=2), args.out)
    elif fmt == "sarif":
        _emit(json.dumps(to_sarif(reports), indent=2), args.out)
    elif fmt == "html":
        _emit(to_html(reports), args.out)
    else:
        _emit(_render_scan_table(reports), args.out)

    return 1 if _fails_gate(reports, args.fail_on) else 0


def _run_rules() -> int:
    from .core import _DANGEROUS_VERBS  # noqa: F401  (kept local; informational)
    catalogue = [
        ("transport.bind_all", "critical", "HTTP transport bound to all interfaces."),
        ("transport.no_tls", "high", "Network transport without TLS."),
        ("transport.no_auth", "high", "Network transport without an auth declaration."),
        ("transport.undeclared", "medium", "No transport type declared."),
        ("transport.unknown_type", "low", "Unrecognized transport type."),
        ("transport.wildcard_origin", "medium", "Wildcard allowed_origins (DNS-rebind)."),
        ("transport.malformed", "high", "transport is not an object or known string."),
        ("capability.tools_mismatch", "high", "Tools exposed but capability not advertised."),
        ("capability.undeclared", "medium", "No capabilities block."),
        ("capability.malformed", "high", "capabilities is not an object."),
        ("capability.tools_empty", "low", "Advertises tools capability but exposes none."),
        ("capability.experimental", "low", "Experimental capabilities enabled."),
        ("tool.no_name", "high", "Tool has no name."),
        ("tool.duplicate_name", "high", "Duplicate tool name."),
        ("tool.no_description", "medium", "Tool has no description."),
        ("tool.thin_description", "low", "Tool description is too short."),
        ("tool.injection_in_description", "critical", "Instruction-smuggling in description."),
        ("tool.danger_no_schema", "high", "Side-effecting tool with no inputSchema."),
        ("tool.danger_no_confirm", "medium", "Side-effecting tool without confirmation."),
        ("tool.schema_open", "medium", "inputSchema additionalProperties=true."),
        ("tool.malformed", "high", "Tool entry is malformed."),
        ("manifest.embedded_secret", "critical", "Embedded credential / token in manifest."),
        ("manifest.unreadable", "high", "Manifest could not be parsed during a scan."),
    ]
    print(f"{TOOL_NAME} {TOOL_VERSION} — {len(catalogue)} detection rules")
    print("=" * 68)
    for rule, sev, desc in catalogue:
        print(f"[{_SEV_LABEL.get(sev, sev.upper())}] {rule:<34} {desc}")
    return 0


def _run_mcp() -> int:
    from .mcp_server import run_mcp_server
    run_mcp_server()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        return _run_audit(args)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules()
    if args.command == "mcp":
        return _run_mcp()
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
