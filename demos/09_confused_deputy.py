"""Scenario 9 - identity / auth architects.

Token passthrough is the quiet killer: a server that forwards the user's bearer
token to downstream tools collapses the auth boundary — everything in context
now wields the user's full authority (a confused deputy). This demo audits a
proxy server that does exactly that, ties it to MCP-TPT-01, and contrasts it
with a server that mints scoped tokens instead.
"""
from _common import fixture, rule, sev

from mcpharden import audit_path, vulndb


def main() -> None:
    rule("CONFUSED DEPUTY  -  token passthrough collapses the auth boundary")

    report = audit_path(fixture("token-passthrough-server.json"))
    print(f"\nServer '{report.server_name}'  score {report.score}/100  "
          f"({'FAIL' if report.failed else 'PASS'})\n")

    for f in report.findings:
        print(f"   [{sev(f.severity)}] {f.rule}")
        print(f"        {f.message}")
        vc = vulndb.BY_RULE.get(f.rule)
        if vc:
            print(f"        class: {vc.id}  {vc.name}")
        print(f"        fix  : {f.remediation}")
        print()

    print("Even with TLS + OAuth/PKCE on the transport, forwarding the user's token")
    print("downstream is the finding. The fix is architectural: mint short-lived,")
    print("audience-scoped tokens per tool — never pass the user's bearer through.")


if __name__ == "__main__":
    main()
