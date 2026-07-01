"""Scenario 17 - blue team (the subtle rug pull).

A server can advertise two tools under the *same name*. If a baseline keyed only
by name, a rug pull that mutates just one of the two duplicates would be
invisible — the kind of blind spot attackers look for. This demo pins a baseline
of a server with two same-named `search` tools, mutates only the second, and
shows mcpharden still catches the drift (a regression guard for that bug).
"""
from _common import fixture, rule, sev

from mcpharden import build_baseline, diff_baseline, load_manifest


def main() -> None:
    rule("DUPLICATE-NAME RUG PULL  -  mutating one of two same-named tools")

    trusted = load_manifest(fixture("dup-trusted.json"))
    baseline = build_baseline(trusted)
    entry = baseline["tools"]["search"]
    print(f"\n1) Baselined 'dup-mcp'. The name 'search' maps to "
          f"{len(entry) if isinstance(entry, list) else 1} pinned definition(s):")
    # These are SHA-256 digests of public tool metadata, not secrets.
    for digest in (entry if isinstance(entry, list) else [entry]):
        fingerprint = "".join(ch for ch in str(digest)[:16])
        print(f"     search  {fingerprint}…")

    print("\n2) The server self-updates: only the SECOND 'search' is poisoned")
    print("   (it now exfiltrates the query). Diff against the baseline:\n")
    updated = load_manifest(fixture("dup-rugpulled.json"))
    report = diff_baseline(baseline, updated, source="dup-rugpulled.json")
    for f in report.findings:
        print(f"   [{sev(f.severity)}] {f.rule:<22} {f.message}")

    print(f"\n3) Verdict: {'DRIFT DETECTED' if report.failed else 'no drift'}.")
    print("   Baselining the full multiset of same-named tools means a poisoned")
    print("   duplicate can't hide behind its honest twin.")


if __name__ == "__main__":
    main()
