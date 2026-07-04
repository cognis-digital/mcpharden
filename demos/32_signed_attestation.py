"""Scenario 32 - compliance / supply chain: a signed hardening attestation.

Auditors want proof: which manifests were scanned, by which tool version, with
what outcome — and evidence it wasn't edited afterward. This demo scans a fleet,
produces an in-toto-style attestation, signs it (HMAC-SHA256), verifies it, then
shows that any tampering with the recorded outcome invalidates the signature.
"""
from _common import fixture, rule

import json

from mcpharden import scan
from mcpharden.report import build_attestation, sign_attestation, verify_attestation


def main() -> None:
    rule("SIGNED ATTESTATION  -  provable, tamper-evident scan evidence")

    # Scan a fleet that includes a poisoned server, so the outcome is a real
    # FAIL and tampering with it is a genuine change to the signed bytes.
    reports = (scan(fixture("registry-fleet"))
               + scan(fixture("exfil-server.json")))
    statement = build_attestation(reports)
    pred = statement["predicate"]
    print(f"\n1) Scanned {pred['servers_scanned']} server(s): "
          f"passed={pred['passed']} total_findings={pred['total_findings']}")
    print("   Each subject is bound to a sha256 over its exact finding set:")
    for subj in statement["subject"]:
        print(f"     {subj['name']:<44} sha256:{subj['digest']['sha256'][:16]}…")

    envelope = sign_attestation(statement, key="ci-attestation-key")
    print(f"\n2) Signed envelope (keyid={envelope['signatures'][0]['keyid']}).")
    print(f"   verify with correct key: {verify_attestation(envelope, 'ci-attestation-key')}")
    print(f"   verify with wrong key  : {verify_attestation(envelope, 'attacker-key')}")

    print("\n3) Tamper with the recorded outcome (claim it passed when it didn't):")
    tampered = json.loads(json.dumps(envelope))
    tampered["statement"]["predicate"]["passed"] = True
    tampered["statement"]["predicate"]["servers_failed"] = 0
    print(f"   verify tampered envelope: {verify_attestation(tampered, 'ci-attestation-key')}")

    print("\nAttach the signed attestation to your release; verifiers detect any edit.")


if __name__ == "__main__":
    main()
