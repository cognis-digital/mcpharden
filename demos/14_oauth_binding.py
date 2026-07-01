"""Scenario 14 - OAuth / session security.

OAuth without PKCE/state leaves authorization codes unbound to the session
(CSRF-style takeover), and a session id carried in a URL is one shoulder-surf or
referer-leak from hijack (MCP-OAUTH-01). This demo audits a server that makes
both mistakes and shows the two findings plus the binding fixes.
"""
from _common import fixture, rule, sev

from mcpharden import audit_path, vulndb


def main() -> None:
    rule("OAUTH BINDING  -  unbound codes and session ids in URLs")

    report = audit_path(fixture("oauth-unbound-server.json"))
    print(f"\nServer '{report.server_name}'  score {report.score}/100  "
          f"({'FAIL' if report.failed else 'PASS'})\n")

    for f in report.findings:
        vc = vulndb.BY_RULE.get(f.rule)
        cls = f"  ({vc.id})" if vc else ""
        print(f"   [{sev(f.severity)}] {f.rule}{cls}")
        print(f"        {f.message}")
        print(f"        fix: {f.remediation}")
        print()

    print("Require PKCE + a session-bound state parameter, and keep session ids out")
    print("of URLs (use rotating, unguessable tokens) to close both takeover paths.")


if __name__ == "__main__":
    main()
