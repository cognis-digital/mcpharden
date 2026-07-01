"""Scenario 15 - multi-server trust.

Cross-server tool shadowing (MCP-TS-01): a malicious server's tool description
tells the agent to route another trusted server's calls through it. This demo
audits a helper server whose `smart_search` description references the *other*
server's `read_file`, catches the shadowing metadata per-server, then runs fleet
posture to show the name-collision precondition the same attack relies on.
"""
from _common import fixture, rule, sev

from mcpharden import audit_path, posture, vulndb


def main() -> None:
    rule("TOOL SHADOWING  -  one server rewriting how you use another")

    report = audit_path(fixture("shadowing-server.json"))
    print(f"\nPer-server audit of '{report.server_name}':\n")
    for f in report.findings:
        vc = vulndb.BY_RULE.get(f.rule)
        cls = f"  ({vc.id})" if vc else ""
        print(f"   [{sev(f.severity)}] {f.rule}{cls}  {f.message}")

    print("\nThe description references another tool's behavior — the shadowing")
    print("signature. The structural precondition is a shared tool name across")
    print("servers, which only a fleet view reveals:\n")

    pr = posture.assess(fixture("fleet"))
    collisions = [f for f in pr.findings if f.rule == "fleet.tool_collision"]
    for f in collisions:
        print(f"   [{sev(f.severity)}] {f.rule}  {f.message}")

    print("\nNamespace tools per server and reject metadata that references other")
    print("servers' tools; remove duplicate registrations so each name resolves once.")


if __name__ == "__main__":
    main()
