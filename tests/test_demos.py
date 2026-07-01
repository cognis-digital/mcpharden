"""Tests for the runnable demo scenarios and their bundled fixtures.

Every scenario must run offline, exit cleanly, and exercise the real API against
the sample manifests in demos/fixtures/. These tests assert both that the demos
run and that the fixtures still produce the findings the demos narrate, so the
demos can't silently drift from the engine.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(REPO_ROOT, "demos")
FIXTURES = os.path.join(DEMOS, "fixtures")
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, DEMOS)

from mcpharden import (  # noqa: E402
    audit_path,
    posture,
    build_baseline,
    diff_baseline,
    load_manifest,
    audit_config_path,
    vulndb,
)


def _fx(*parts):
    return os.path.join(FIXTURES, *parts)


class TestDemoScenariosRun(unittest.TestCase):
    """Each scenario's main() runs offline and prints output without raising."""

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

    def test_twenty_scenarios_registered(self):
        self.assertEqual(len(self.SCENARIOS), 20)

    def test_each_scenario_runs(self):
        import importlib

        for name in self.SCENARIOS:
            with self.subTest(scenario=name):
                mod = importlib.import_module(name)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    mod.main()
                self.assertTrue(buf.getvalue().strip(), f"{name} produced no output")

    def test_run_all_includes_every_scenario(self):
        import importlib

        run_all = importlib.import_module("run_all")
        self.assertEqual(run_all.SCENARIOS, self.SCENARIOS)

    def test_run_all(self):
        import importlib

        run_all = importlib.import_module("run_all")
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_all.main()
        self.assertIn("All demo scenarios completed", buf.getvalue())


class TestFixtureFindings(unittest.TestCase):
    """The fixtures must keep producing the findings the demos describe."""

    def test_hardened_server_passes(self):
        r = audit_path(_fx("hardened-server.json"))
        self.assertFalse(r.failed, r.to_dict())
        self.assertEqual(r.score, 100)

    def test_poisoned_server_is_tool_poisoning(self):
        r = audit_path(_fx("poisoned-server.json"))
        rules = {f.rule for f in r.findings}
        self.assertIn("tool.injection_in_description", rules)
        self.assertIn("tool.mutable_registration", rules)
        # And it maps to the catalog class the auditor demo cites.
        self.assertEqual(vulndb.BY_RULE["tool.injection_in_description"].id, "MCP-TP-01")

    def test_public_rce_server_is_critical(self):
        r = audit_path(_fx("public-rce-server.json"))
        rules = {f.rule for f in r.findings}
        self.assertTrue(r.failed)
        for expected in ("transport.bind_all", "tool.shell_exec",
                         "manifest.embedded_secret", "transport.cors_wildcard"):
            self.assertIn(expected, rules)

    def test_rugpull_diff_detects_drift(self):
        base = build_baseline(load_manifest(_fx("payments-trusted.json")))
        report = diff_baseline(base, load_manifest(_fx("payments-rugpulled.json")))
        rules = {f.rule for f in report.findings}
        self.assertTrue(report.failed)
        self.assertIn("rugpull.tool_changed", rules)   # send_payment mutated
        self.assertIn("rugpull.tool_added", rules)     # export_history added

    def test_fleet_posture_correlations(self):
        pr = posture.assess(_fx("fleet"))
        rules = {f.rule for f in pr.findings}
        self.assertIn("fleet.shared_secret", rules)
        self.assertIn("fleet.tool_collision", rules)
        self.assertIn("fleet.lateral_movement", rules)
        self.assertEqual(pr.grade, "F")
        self.assertTrue(pr.failed)

    def test_client_config_findings(self):
        r = audit_config_path(_fx("claude_desktop_config.json"))
        rules = {f.rule for f in r.findings}
        self.assertIn("config.unpinned_command", rules)
        self.assertIn("config.secret_in_env", rules)
        self.assertIn("config.shell_exec", rules)
        self.assertIn("config.auto_approve", rules)


class TestNewFixtureFindings(unittest.TestCase):
    """Fixtures added for scenarios 06-20 must keep producing what they narrate."""

    def _rules(self, name):
        return {f.rule for f in audit_path(_fx(name)).findings}

    def test_token_passthrough_fixture(self):
        self.assertIn("auth.token_passthrough", self._rules("token-passthrough-server.json"))

    def test_sampling_dos_fixture(self):
        r = audit_path(_fx("sampling-dos-server.json"))
        rules = {f.rule for f in r.findings}
        self.assertIn("capabilities.sampling_unbounded", rules)
        # medium-only: default critical/high gate must NOT fail it.
        self.assertFalse(r.failed)

    def test_oauth_unbound_fixture(self):
        rules = self._rules("oauth-unbound-server.json")
        self.assertIn("auth.oauth_unbound", rules)
        self.assertIn("auth.session_in_url", rules)

    def test_shadowing_fixture(self):
        self.assertIn("tool.shadowing", self._rules("shadowing-server.json"))

    def test_unpinned_fixture(self):
        self.assertIn("transport.unpinned_command", self._rules("unpinned-server.json"))

    def test_line_jump_fixture_has_control_chars(self):
        self.assertIn("tool.control_chars", self._rules("line-jump-server.json"))

    def test_wildcard_origin_mixed_list_fixture(self):
        self.assertIn("transport.wildcard_origin", self._rules("wildcard-origin-server.json"))

    def test_clean_fleet_grades_a(self):
        pr = posture.assess(_fx("clean-fleet"))
        self.assertEqual(pr.grade, "A")
        self.assertFalse(pr.failed)
        self.assertEqual(len(pr.findings), 0)

    def test_duplicate_name_rugpull_caught(self):
        base = build_baseline(load_manifest(_fx("dup-trusted.json")))
        # the trusted fixture has two tools both named 'search'
        self.assertIsInstance(base["tools"]["search"], list)
        r = diff_baseline(base, load_manifest(_fx("dup-rugpulled.json")))
        self.assertIn("rugpull.tool_changed", {f.rule for f in r.findings})
        self.assertTrue(r.failed)

    def test_clean_client_config_passes(self):
        r = audit_config_path(_fx("clean_client_config.json"))
        self.assertFalse(r.failed, r.to_dict())
        self.assertEqual(r.findings, [])

    def test_malformed_dir_scan_resilient(self):
        from mcpharden import scan
        reports = scan(_fx("malformed"))
        rules = {f.rule for r in reports for f in r.findings}
        # at least one unreadable, and the scan still returns multiple reports
        self.assertIn("manifest.unreadable", rules)
        self.assertGreaterEqual(len(reports), 3)


if __name__ == "__main__":
    unittest.main()
