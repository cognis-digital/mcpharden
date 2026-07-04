"""Run the 2026 capability-multiplier demo scenarios end to end.

    python demos/run_multiply.py

Covers the additive features: policy-driven CI gate, fleet baseline registry,
signed attestations, JUnit export, and exfiltration detection. Each scenario is
independent, runs fully offline against bundled fixtures, and exits 0.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCENARIOS = [
    "30_ci_gate_policy",
    "31_fleet_registry_rugpull",
    "32_signed_attestation",
    "33_junit_and_exfil",
]


def main() -> None:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 70)
    print("  All capability-multiplier demo scenarios completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
