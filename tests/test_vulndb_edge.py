"""Edge-case tests for the MCP vulnerability catalog (mcpharden.vulndb).

Pins the catalog's integrity invariants (unique ids, valid severities, every
detect_rule maps to a real catalog entry), the CVE lookups, and that the rules
the engine actually emits are covered by the taxonomy where claimed.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpharden import vulndb  # noqa: E402
from mcpharden.core import SEVERITY_ORDER  # noqa: E402


class TestCatalogIntegrity(unittest.TestCase):
    def test_non_empty(self):
        self.assertGreaterEqual(len(vulndb.CATALOG), 10)

    def test_unique_ids(self):
        ids = [v.id for v in vulndb.CATALOG]
        self.assertEqual(len(ids), len(set(ids)))

    def test_valid_severities(self):
        for v in vulndb.CATALOG:
            self.assertIn(v.severity, SEVERITY_ORDER, v.id)

    def test_every_entry_has_summary_and_remediation(self):
        for v in vulndb.CATALOG:
            self.assertTrue(v.summary.strip(), v.id)
            self.assertTrue(v.remediation.strip(), v.id)

    def test_every_entry_has_a_reference(self):
        for v in vulndb.CATALOG:
            self.assertTrue(v.references, v.id)

    def test_by_id_map_complete(self):
        self.assertEqual(len(vulndb.BY_ID), len(vulndb.CATALOG))
        for v in vulndb.CATALOG:
            self.assertIs(vulndb.BY_ID[v.id], v)

    def test_by_rule_only_non_none(self):
        self.assertNotIn(None, vulndb.BY_RULE)
        for rule, v in vulndb.BY_RULE.items():
            self.assertEqual(v.detect_rule, rule)

    def test_detect_rules_unique(self):
        rules = [v.detect_rule for v in vulndb.CATALOG if v.detect_rule]
        self.assertEqual(len(rules), len(set(rules)))


class TestCveLookup(unittest.TestCase):
    def test_known_cve(self):
        hits = vulndb.by_cve("CVE-2025-54136")
        self.assertTrue(hits)
        self.assertTrue(any(v.id == "MCP-TP-01" for v in hits))

    def test_cve_case_insensitive(self):
        self.assertEqual([v.id for v in vulndb.by_cve("cve-2025-54136")],
                         [v.id for v in vulndb.by_cve("CVE-2025-54136")])

    def test_unknown_cve_empty(self):
        self.assertEqual(vulndb.by_cve("CVE-0000-00000"), [])

    def test_all_cves_unique_and_nonempty(self):
        cves = vulndb.all_cves()
        self.assertTrue(cves)
        self.assertEqual(len(cves), len(set(cves)))

    def test_command_injection_has_many_cves(self):
        ci = vulndb.BY_ID["MCP-CI-01"]
        self.assertGreaterEqual(len(ci.cves), 3)


class TestToDict(unittest.TestCase):
    def test_to_dict_json_safe(self):
        import json
        for v in vulndb.CATALOG:
            d = v.to_dict()
            json.dumps(d)
            self.assertEqual(d["id"], v.id)


class TestEngineRuleCoverage(unittest.TestCase):
    """The headline attack classes must each have a detect_rule the engine emits."""

    def test_core_classes_mapped(self):
        for rule in ("tool.injection_in_description", "tool.shell_exec",
                     "transport.cors_wildcard", "transport.bind_all",
                     "transport.unpinned_command", "tool.mutable_registration",
                     "auth.token_passthrough", "tool.auto_approve"):
            self.assertIn(rule, vulndb.BY_RULE, f"{rule} should map to a catalog class")


if __name__ == "__main__":
    unittest.main()
