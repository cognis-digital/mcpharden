"""Run every mcpharden demo scenario end to end.

    python demos/run_all.py

Each scenario is independent, runs fully offline against the bundled sample
manifests in demos/fixtures/, prints narrated output, and exits 0 — so they
double as smoke tests for the real API.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCENARIOS = [
    "01_ai_platform_review",
    "02_server_author_lint",
    "03_auditor_cve_mapping",
    "04_blue_team_rugpull",
    "05_red_team_fleet_posture",
    "06_compliance_sarif_export",
    "07_client_config_audit",
    "08_malformed_resilience",
    "09_confused_deputy",
    "10_line_jumping",
    "11_supply_chain_pinning",
    "12_cors_dns_rebinding",
    "13_sampling_dos",
    "14_oauth_binding",
    "15_tool_shadowing",
    "16_clean_fleet_grade",
    "17_duplicate_tool_rugpull",
    "18_ci_gate_policy",
    "19_wildcard_origin_bugfix",
    "20_mcp_server_selfscan",
]


def main() -> None:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 70)
    print("  All demo scenarios completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
