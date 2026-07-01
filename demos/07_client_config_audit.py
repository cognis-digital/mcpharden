"""Scenario 7 - end users / IT admins.

The real MCP risk surface for most people isn't an abstract server manifest — it's
the `mcpServers` block they pasted into Claude Desktop / Cursor / Cline / VS Code.
This demo audits a realistic (risky) client config, walks each flagged server, and
then audits a hardened config that passes — the before/after an admin would apply.
"""
from _common import fixture, rule, sev

from mcpharden.configaudit import audit_config_path


def _walk(path, label):
    report = audit_config_path(fixture(path))
    print(f"\n{label}: {report.server_name}  ({'FAIL' if report.failed else 'PASS'})")
    if not report.findings:
        print("   (no findings — every registered server is safe to load)")
        return
    for f in report.findings:
        print(f"   [{sev(f.severity)}] {f.rule:<26} {f.message}")


def main() -> None:
    rule("CLIENT CONFIG AUDIT  -  the servers you actually registered")

    _walk("claude_desktop_config.json", "Risky config as pasted")
    print("\n   Each line is a server you trusted with your machine and tokens.")

    _walk("clean_client_config.json", "Hardened config")

    print("\nRun `mcpharden configscan` with no argument to auto-detect and audit")
    print("your real Claude Desktop / Cursor / VS Code config in place.")


if __name__ == "__main__":
    main()
