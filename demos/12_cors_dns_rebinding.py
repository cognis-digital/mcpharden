"""Scenario 12 - network / infrastructure security.

An SSE/HTTP MCP server with wildcard CORS and no Origin check is reachable from a
victim's browser via DNS rebinding, pulling an attacker into internal MCP
services (MCP-SSE-01). This demo audits a public RCE server that combines bind-all,
no-TLS, and wildcard CORS, and isolates the network-exposure findings that make
it a rebinding target.
"""
from _common import fixture, rule, sev

from mcpharden import audit_path, vulndb


_NET_RULES = {"transport.bind_all", "transport.no_tls", "transport.no_auth",
              "transport.cors_wildcard", "transport.wildcard_origin"}


def main() -> None:
    rule("DNS REBINDING  -  wildcard CORS turns a browser into your attacker")

    report = audit_path(fixture("public-rce-server.json"))
    net = [f for f in report.findings if f.rule in _NET_RULES]

    print(f"\nServer '{report.server_name}'  score {report.score}/100\n")
    print("Network-exposure findings (the rebinding pre-conditions):\n")
    for f in net:
        vc = vulndb.BY_RULE.get(f.rule)
        cls = f"  ({vc.id})" if vc else ""
        print(f"   [{sev(f.severity)}] {f.rule}{cls}")
        print(f"        {f.message}")
        print()

    print("Combined, these mean any web page the user visits can reach this server")
    print("and drive its tools. The fix: bind 127.0.0.1, validate Origin, drop")
    print("wildcard CORS, require auth + TLS on every SSE/HTTP request.")


if __name__ == "__main__":
    main()
