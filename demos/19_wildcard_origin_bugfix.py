"""Scenario 19 - detector fidelity (a real bug, fixed).

A network server can list explicit allowed origins *and* sneak a `"*"` into the
same list — `["https://trusted", "*"]`. The wildcard still means "any origin",
but an equality check (`origins == ["*"]`) would miss it. mcpharden now flags a
wildcard anywhere in the list. This demo audits exactly that manifest and proves
the `transport.wildcard_origin` finding fires on the mixed list.
"""
from _common import fixture, rule, sev

from mcpharden import audit_manifest, audit_path


def main() -> None:
    rule("DETECTOR FIDELITY  -  wildcard hidden in a list of real origins")

    report = audit_path(fixture("wildcard-origin-server.json"))
    fired = any(f.rule == "transport.wildcard_origin" for f in report.findings)

    print("\nManifest allowed_origins: [\"https://studio.cognis.digital\", \"*\"]")
    print(f"Server '{report.server_name}'  score {report.score}/100\n")
    for f in report.findings:
        if f.rule == "transport.wildcard_origin":
            print(f"   [{sev(f.severity)}] {f.rule}  {f.message}")
            print(f"        fix: {f.remediation}")

    print(f"\nWildcard-in-mixed-list detected: {fired}")

    # Contrast: explicit-only origins must NOT trip the finding (no false positive).
    explicit = audit_manifest({
        "name": "api-mcp",
        "transport": {"type": "http", "host": "127.0.0.1", "tls": True,
                      "auth": {"type": "oauth2", "pkce": True, "state": True},
                      "allowed_origins": ["https://studio.cognis.digital"]},
        "capabilities": {"tools": {}},
        "tools": [{"name": "ping", "description": "Health check.",
                   "inputSchema": {"type": "object", "additionalProperties": False}}],
    })
    clean = not any(f.rule == "transport.wildcard_origin" for f in explicit.findings)
    print(f"Explicit-only origins stays clean (no false positive): {clean}")


if __name__ == "__main__":
    main()
