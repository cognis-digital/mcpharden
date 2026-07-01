"""Scenario 16 - platform owners (the good outcome).

Most demos show what failure looks like; this one shows the target state. A
well-built fleet — every server on localhost with TLS + OAuth/PKCE, distinct
scoped credentials, namespaced tools — should grade A with zero cross-server
correlations. This demo asserts that the hardened reference fleet does, so teams
know what "done" looks like and can diff their own deployment against it.
"""
from _common import fixture, rule

from mcpharden import posture


def main() -> None:
    rule("CLEAN FLEET  -  what a hardened deployment scores")

    pr = posture.assess(fixture("clean-fleet"))

    print(f"\nFleet of {pr.server_count} server(s), {pr.network_count} network-reachable.")
    print("Per-server scores:\n")
    for s in pr.servers:
        reach = "net  " if s.network else "local"
        print(f"   [{'FAIL' if s.failed else 'PASS'}] {s.score:>3}/100  {reach}  {s.name}")

    print(f"\nCross-server correlations: {len(pr.findings)}")
    print(f"Fleet hardening grade    : {pr.grade}  ({pr.fleet_score}/100)")
    print(f"Result                   : {'FAIL' if pr.failed else 'PASS'}")

    print("\nThis is the bar: localhost + TLS + OAuth/PKCE on every network server,")
    print("distinct scoped tokens, namespaced tools. Diff your fleet against it.")


if __name__ == "__main__":
    main()
