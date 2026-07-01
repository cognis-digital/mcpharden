"""Deep tests for the SARIF 2.1.0 and HTML output, and the connect mapping.

SARIF is the format GitHub code-scanning ingests, so its structure has a strict
contract: schema/version, a driver with deduped rules, per-finding results with
levels and security-severity, and physical/logical locations. These tests pin
that contract field by field so a refactor can't silently break code-scanning
upload. Also covers the connect.map_record finding-normalization (no optional dep).
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpharden import Finding, Report, to_sarif, to_html  # noqa: E402
import mcpharden.connect as connect  # noqa: E402


def _report(*findings):
    return Report("path/to/server.json", "srv", list(findings))


class TestSarifStructure(unittest.TestCase):
    def setUp(self):
        self.sarif = to_sarif([_report(
            Finding("transport.bind_all", "critical", "binds all", "transport.host", "bind localhost"),
            Finding("tool.thin_description", "low", "short desc", "tools[0]", "expand it"),
        )])

    def test_schema_and_version(self):
        self.assertIn("sarif", self.sarif["$schema"])
        self.assertEqual(self.sarif["version"], "2.1.0")

    def test_single_run(self):
        self.assertEqual(len(self.sarif["runs"]), 1)

    def test_driver_metadata(self):
        driver = self.sarif["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "mcpharden")
        self.assertIn("informationUri", driver)

    def test_two_results(self):
        self.assertEqual(len(self.sarif["runs"][0]["results"]), 2)

    def test_levels_mapped(self):
        levels = {r["ruleId"]: r["level"] for r in self.sarif["runs"][0]["results"]}
        self.assertEqual(levels["transport.bind_all"], "error")
        self.assertEqual(levels["tool.thin_description"], "note")

    def test_security_severity_on_rules(self):
        rules = {r["id"]: r for r in self.sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(rules["transport.bind_all"]["properties"]["security-severity"], "9.5")
        self.assertEqual(rules["tool.thin_description"]["properties"]["security-severity"], "3.0")

    def test_result_has_location(self):
        res = self.sarif["runs"][0]["results"][0]
        loc = res["locations"][0]["physicalLocation"]
        self.assertIn("artifactLocation", loc)
        self.assertIn("uri", loc["artifactLocation"])

    def test_remediation_in_message(self):
        res = next(r for r in self.sarif["runs"][0]["results"]
                   if r["ruleId"] == "transport.bind_all")
        self.assertIn("Remediation", res["message"]["text"])

    def test_uri_uses_forward_slashes(self):
        rep = Report(os.path.join("a", "b", "c.json"), "s", [Finding("r", "high", "m")])
        sarif = to_sarif([rep])
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertNotIn("\\", uri)


class TestSarifLevelMapping(unittest.TestCase):
    def test_all_severities_map(self):
        expected = {"critical": "error", "high": "error", "medium": "warning",
                    "low": "note", "info": "note"}
        for sev, level in expected.items():
            sarif = to_sarif([_report(Finding("r", sev, "m"))])
            self.assertEqual(sarif["runs"][0]["results"][0]["level"], level, sev)

    def test_empty_produces_valid_doc(self):
        sarif = to_sarif([])
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"], [])

    def test_clean_report_no_results(self):
        sarif = to_sarif([_report()])
        self.assertEqual(sarif["runs"][0]["results"], [])


class TestHtmlOutput(unittest.TestCase):
    def test_overall_pass(self):
        html = to_html([_report()])
        self.assertIn("RESULT: PASS", html)

    def test_overall_fail(self):
        html = to_html([_report(Finding("r", "critical", "m"))])
        self.assertIn("RESULT: FAIL", html)

    def test_severity_badges_present(self):
        html = to_html([_report(Finding("transport.bind_all", "critical", "m"))])
        self.assertIn("CRITICAL", html)

    def test_score_rendered(self):
        html = to_html([_report(Finding("r", "low", "m"))])
        self.assertIn("/100", html)

    def test_multiple_servers_each_rendered(self):
        html = to_html([Report("a.json", "alpha", []), Report("b.json", "bravo", [])])
        self.assertIn("alpha", html)
        self.assertIn("bravo", html)

    def test_html_is_self_contained(self):
        html = to_html([_report(Finding("r", "high", "m"))])
        # no external resources
        self.assertNotIn("http://", html.replace("https://github.com", ""))
        self.assertNotIn("<script src", html)


class TestConnectMapping(unittest.TestCase):
    def test_map_record_preserves_and_enriches(self):
        out = connect.map_record({"rule": "tool.shell_exec", "severity": "critical",
                                  "message": "RCE", "cve": "CVE-2025-54073"})
        self.assertEqual(out["title"], "tool.shell_exec")
        self.assertEqual(out["severity"], "critical")
        self.assertEqual(out["description"], "RCE")
        self.assertEqual(out["cve"], "CVE-2025-54073")

    def test_map_record_defaults_severity_info(self):
        out = connect.map_record({"rule": "x"})
        self.assertEqual(out["severity"], "info")

    def test_map_record_is_dict(self):
        self.assertIsInstance(connect.map_record({}), dict)

    def test_map_record_never_raises(self):
        # even on odd input it returns a dict (safe-fallback contract)
        self.assertIsInstance(connect.map_record({"rule": None, "tags": None}), dict)


if __name__ == "__main__":
    unittest.main()
