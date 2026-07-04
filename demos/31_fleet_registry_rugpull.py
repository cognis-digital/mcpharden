"""Scenario 31 - fleet operator: pin the WHOLE fleet, catch any rug pull.

`baseline`/`diff` pin one server. A real agent host trusts a fleet, and any one
server can rug-pull independently, or a brand-new unreviewed server can quietly
join the trust boundary. This demo pins every server in a directory into one
signed registry, then verifies a week-later snapshot against it — catching, in a
single pass: a mutated tool (rug pull), and an unreviewed server that appeared.
"""
from _common import fixture, rule, sev

import json

from mcpharden.registry import (
    build_registry,
    load_registry,
    sign_registry,
    verify_registry,
)
from mcpharden.report import verify_attestation


def main() -> None:
    rule("FLEET REGISTRY  -  one signed baseline for the whole deployment")

    trusted = fixture("registry-fleet")
    registry = build_registry(trusted)
    print(f"\n1) Pinned {registry['server_count']} server(s) when the fleet was trusted:")
    for name, entry in sorted(registry["servers"].items()):
        print(f"     {name:<16} {len(entry['tools'])} tool(s)")

    signed = sign_registry(registry, key="fleet-signing-key")
    print("\n2) Signed the registry (HMAC-SHA256) so tampering is detectable:")
    print(f"     keyid={signed['signatures'][0]['keyid']}  "
          f"valid={verify_attestation(signed, 'fleet-signing-key')}")

    # round-trip the signed registry through JSON (as a file would be)
    reloaded = load_registry_from_obj(signed, "fleet-signing-key")

    print("\n3) A week later, verify the live fleet against the pinned registry:\n")
    reports = verify_registry(reloaded, fixture("registry-fleet-drifted"))
    for r in reports:
        for f in r.findings:
            print(f"   [{sev(f.severity)}] {f.rule:<26} {r.server_name}: {f.message[:70]}")

    changed = sum(1 for r in reports for f in r.findings if f.rule == "rugpull.tool_changed")
    unreg = sum(1 for r in reports for f in r.findings if f.rule == "fleet.server_unregistered")
    print(f"\n4) Verdict: {changed} rug-pulled tool(s), {unreg} unreviewed new server(s).")
    print("   'orders-mcp/get_order' was mutated to leak payment details; a new")
    print("   'shipping-mcp' joined the trust boundary without review.")
    print("\nPin the fleet into a signed registry; run `registry verify` in CI.")


def load_registry_from_obj(signed_obj, key):
    """Simulate writing the signed registry to disk and loading it back."""
    import tempfile
    import os
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(signed_obj, fh)
        return load_registry(path, key=key)
    finally:
        os.unlink(path)


if __name__ == "__main__":
    main()
