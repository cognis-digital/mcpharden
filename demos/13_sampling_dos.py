"""Scenario 13 - FinOps / abuse prevention.

A server that exposes the `sampling` capability with no rate limit lets a caller
drain model credits or wedge the host with unbounded generations (MCP-SAMP-01).
This is a medium-severity finding that won't fail a critical/high gate — exactly
why it's easy to miss. This demo shows how to surface it with a stricter
`--fail-on medium`-style policy in code.
"""
from _common import fixture, rule, sev

from mcpharden import audit_path, vulndb

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def main() -> None:
    rule("SAMPLING DoS  -  the medium-severity finding a high gate ignores")

    report = audit_path(fixture("sampling-dos-server.json"))
    print(f"\nServer '{report.server_name}'  score {report.score}/100  "
          f"default-gate failed={report.failed}\n")

    for f in report.findings:
        vc = vulndb.BY_RULE.get(f.rule)
        cls = f"  ({vc.id})" if vc else ""
        print(f"   [{sev(f.severity)}] {f.rule}{cls}  {f.message}")
        print(f"        fix: {f.remediation}")

    # Demonstrate a stricter admission policy that catches medium findings.
    threshold = SEV_ORDER["medium"]
    fails_strict = any(SEV_ORDER.get(f.severity, 9) <= threshold for f in report.findings)
    print(f"\nDefault `--fail-on high` would ADMIT this server (no critical/high).")
    print(f"Stricter `--fail-on medium` BLOCKS it: {fails_strict}")
    print("\nRate-limit and quota sampling/paid tools; alert on spend anomalies, and")
    print("tighten your CI gate to medium for servers that can spend money.")


if __name__ == "__main__":
    main()
