"""Scenario 18 - CI/CD engineers.

A hardening linter is only useful if it can fail a build. This demo models the
exact admission logic `mcpharden scan --fail-on <sev>` applies: it scans every
bundled server, then evaluates three gate policies (critical / high / medium)
and prints which servers each policy admits or blocks — so a team can pick the
gate strictness that matches their risk tolerance and wire it into CI.
"""
from _common import fixture, rule

from mcpharden import scan

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _blocks(report, gate):
    threshold = SEV_ORDER[gate]
    return any(SEV_ORDER.get(f.severity, 9) <= threshold for f in report.findings)


def main() -> None:
    rule("CI GATE POLICY  -  pick the strictness, fail the build")

    reports = scan(fixture("fleet"))
    gates = ("critical", "high", "medium")

    header = f"   {'server':<16}" + "".join(f"{g:>10}" for g in gates)
    print("\n" + header)
    print("   " + "-" * (16 + 10 * len(gates)))
    for r in reports:
        cells = "".join(f"{'BLOCK' if _blocks(r, g) else 'admit':>10}" for g in gates)
        print(f"   {r.server_name:<16}{cells}")

    print("\nFor each gate, how many of the fleet's servers would the build reject?")
    for g in gates:
        blocked = sum(1 for r in reports if _blocks(r, g))
        print(f"   --fail-on {g:<9} blocks {blocked}/{len(reports)} server(s)")

    print("\nStart at `--fail-on high` (block critical+high), tighten to medium for")
    print("servers that can spend money or touch production. The gate is one flag.")


if __name__ == "__main__":
    main()
