"""Scenario 11 - supply-chain / DevSecOps.

Launching an MCP server with `npx -y some-pkg` (or `uvx`, `bunx`) pulls and runs
whatever the latest published release is — a poisoned version executes on your
host (MCP-SC-01). This demo audits an unpinned server, shows the finding, then
audits the same server pinned to an exact version and watches the finding clear.
"""
from _common import fixture, rule, sev

from mcpharden import audit_manifest, audit_path, vulndb


def main() -> None:
    rule("SUPPLY CHAIN  -  pin the launch command or run the attacker's release")

    report = audit_path(fixture("unpinned-server.json"))
    print(f"\nUnpinned server '{report.server_name}'  "
          f"({'FAIL' if report.failed else 'PASS'})\n")
    for f in report.findings:
        vc = vulndb.BY_RULE.get(f.rule)
        cls = f"  ({vc.id})" if vc else ""
        print(f"   [{sev(f.severity)}] {f.rule}{cls}")
        print(f"        {f.message}")
        print(f"        fix: {f.remediation}\n")

    print("Now pin the package to an exact version (weather-mcp-server@1.4.2):\n")
    pinned = {
        "name": "weather-mcp", "transport": {"type": "stdio", "command": "npx",
            "args": ["-y", "weather-mcp-server@1.4.2"]},
        "capabilities": {"tools": {}},
        "tools": [{"name": "forecast",
                   "description": "Return the weather forecast for a lat/lon pair.",
                   "inputSchema": {"type": "object", "additionalProperties": False}}],
    }
    fixed = audit_manifest(pinned)
    rules = {f.rule for f in fixed.findings}
    cleared = "transport.unpinned_command" not in rules
    print(f"   pinned -> score {fixed.score}/100  "
          f"unpinned finding cleared: {cleared}")
    print("\nPin every npx/uvx/bunx package to a version or hash and lock dependencies.")


if __name__ == "__main__":
    main()
