"""Scenario 8 - tooling / robustness.

A scanner that crashes on the first bad file is useless in CI, where one
hand-edited manifest can be broken JSON, a JSON array, empty, or full of
wrong-typed fields. This demo points mcpharden at a directory of deliberately
malformed manifests and shows it degrades gracefully: each bad file becomes a
single `manifest.unreadable` finding, the scan still completes, and a partially
valid manifest still gets real findings.
"""
from _common import fixture, rule, sev

from mcpharden import scan, load_manifest, ManifestError


def main() -> None:
    rule("RESILIENCE  -  malformed manifests degrade, they don't crash")

    print("\n1) Direct load() of each bad file raises a clear ManifestError:\n")
    for name in ("malformed/bad-json.json", "malformed/array-root.json",
                 "malformed/empty.json"):
        try:
            load_manifest(fixture(name))
            print(f"   {name}: (unexpectedly parsed)")
        except (ManifestError, OSError) as exc:
            short = str(exc).splitlines()[0][:60]
            print(f"   {name:<28} -> ManifestError: {short}")

    print("\n2) scan() over the whole malformed/ directory never aborts:\n")
    reports = scan(fixture("malformed"))
    for r in reports:
        rules = sorted({f.rule for f in r.findings})
        print(f"   {r.server_name:<22} {rules}")

    unreadable = sum(1 for r in reports for f in r.findings
                     if f.rule == "manifest.unreadable")
    print(f"\nScanned {len(reports)} file(s); {unreadable} unreadable, the rest still")
    print("produced real findings. One broken file never blocks the others.")


if __name__ == "__main__":
    main()
