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


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="MCP server hardening linter — audits capability "
                    "declarations, transport, and tool descriptions.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    audit = sub.add_parser(
        "audit", help="Audit an MCP server manifest (JSON) for weaknesses.")
    audit.add_argument("manifest", help="Path to the MCP server manifest JSON.")
    audit.add_argument("--format", choices=("table", "json"), default="table",
                       help="Output format (default: table).")
    audit.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER),
                       default="info",
                       help="Only report findings at or above this severity.")
    return p


def _run_audit(args: argparse.Namespace) -> int:
    try:
        manifest = load_manifest(args.manifest)
    except (OSError, ManifestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = audit_manifest(manifest, source=args.manifest)

    threshold = SEVERITY_ORDER[args.min_severity]
    report.findings = [
        f for f in report.findings
        if SEVERITY_ORDER.get(f.severity, 99) <= threshold
    ]

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render_table(report))

    return 1 if report.failed else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        return _run_audit(args)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
