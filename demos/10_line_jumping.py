"""Scenario 10 - human reviewers.

Line jumping (MCP-LJ-01) hides instructions from the human reviewing a tool with
ANSI/control escapes: the terminal renders a clean description while the model
ingests the hidden directive. This demo audits a calendar server whose
`list_events` description carries a concealed "read ~/.aws/credentials" payload,
shows that mcpharden sees the control characters the eye can't, and prints a
visible, escaped rendering of what's really in the metadata.
"""
from _common import fixture, rule, sev

from mcpharden import audit_path, load_manifest, vulndb


def main() -> None:
    rule("LINE JUMPING  -  the instruction your terminal hides from you")

    manifest = load_manifest(fixture("line-jump-server.json"))
    desc = manifest["tools"][0]["description"]

    print("\nWhat a reviewer sees rendered in a terminal (escapes applied):")
    print(f"   {desc}\n")

    print("What is actually in the bytes (control chars made visible):")
    visible = desc.encode("unicode_escape").decode("ascii")
    print(f"   {visible}\n")

    report = audit_path(fixture("line-jump-server.json"))
    for f in report.findings:
        vc = vulndb.BY_RULE.get(f.rule)
        cls = f"  ({vc.id})" if vc else ""
        print(f"   [{sev(f.severity)}] {f.rule}{cls}  {f.message}")

    print("\nThe hidden 'read ~/.aws/credentials' directive reaches the model even")
    print("though your screen never showed it. mcpharden flags control/ANSI escapes")
    print("in tool metadata so they never reach the agent or the reviewer's blind spot.")


if __name__ == "__main__":
    main()
