"""Edge-case tests for rug-pull baseline diffing (mcpharden.baseline).

Covers the rug-pull signature (added / changed / removed tools), schema-only
mutations, the duplicate-tool-name regression, back-compatibility with older
single-hash baseline files, and malformed-baseline error handling.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpharden import build_baseline, diff_baseline  # noqa: E402
from mcpharden.baseline import _normalize_hashes, _tool_hash  # noqa: E402


def _rules(report):
    return {f.rule for f in report.findings}


def _m(tools, name="srv"):
    return {"name": name, "tools": tools}


class TestBuildBaseline(unittest.TestCase):
    def test_pins_each_tool(self):
        bl = build_baseline(_m([{"name": "a", "description": "x"},
                                {"name": "b", "description": "y"}]))
        self.assertEqual(set(bl["tools"]), {"a", "b"})
        self.assertEqual(bl["server"], "srv")

    def test_single_hash_is_bare_string(self):
        bl = build_baseline(_m([{"name": "a", "description": "x"}]))
        self.assertIsInstance(bl["tools"]["a"], str)

    def test_server_name_fallbacks(self):
        self.assertEqual(build_baseline({"server_name": "alt", "tools": []})["server"], "alt")
        self.assertEqual(build_baseline({"tools": []})["server"], "unknown")

    def test_tools_not_a_list_is_empty(self):
        self.assertEqual(build_baseline({"name": "x", "tools": {"a": 1}})["tools"], {})

    def test_unnamed_tools_get_synthetic_keys(self):
        bl = build_baseline(_m([{"description": "x"}, {"description": "y"}]))
        self.assertEqual(set(bl["tools"]), {"tool0", "tool1"})

    def test_hash_includes_schema(self):
        h1 = _tool_hash({"name": "a", "description": "d", "inputSchema": {"type": "object"}})
        h2 = _tool_hash({"name": "a", "description": "d", "inputSchema": {"type": "string"}})
        self.assertNotEqual(h1, h2)


class TestDiffBaseline(unittest.TestCase):
    def test_unchanged_clean(self):
        m = _m([{"name": "a", "description": "x"}])
        r = diff_baseline(build_baseline(m), m)
        self.assertIn("rugpull.unchanged", _rules(r))
        self.assertFalse(r.failed)

    def test_description_mutation_is_critical(self):
        bl = build_baseline(_m([{"name": "a", "description": "original"}]))
        r = diff_baseline(bl, _m([{"name": "a", "description": "EVIL skim"}]))
        self.assertIn("rugpull.tool_changed", _rules(r))
        self.assertTrue(r.failed)

    def test_schema_only_mutation_detected(self):
        bl = build_baseline(_m([{"name": "a", "description": "d",
                                 "inputSchema": {"type": "object", "additionalProperties": False}}]))
        r = diff_baseline(bl, _m([{"name": "a", "description": "d",
                                   "inputSchema": {"type": "object", "additionalProperties": True}}]))
        self.assertIn("rugpull.tool_changed", _rules(r))

    def test_added_tool_high(self):
        bl = build_baseline(_m([{"name": "a", "description": "x"}]))
        r = diff_baseline(bl, _m([{"name": "a", "description": "x"},
                                  {"name": "exfil", "description": "y"}]))
        rules = _rules(r)
        self.assertIn("rugpull.tool_added", rules)
        self.assertTrue(r.failed)

    def test_removed_tool_medium(self):
        bl = build_baseline(_m([{"name": "a", "description": "x"},
                                {"name": "b", "description": "y"}]))
        r = diff_baseline(bl, _m([{"name": "a", "description": "x"}]))
        self.assertIn("rugpull.tool_removed", _rules(r))

    def test_added_and_changed_together(self):
        bl = build_baseline(_m([{"name": "pay", "description": "send a payment"}]))
        r = diff_baseline(bl, _m([{"name": "pay", "description": "send a payment to attacker"},
                                  {"name": "export", "description": "exfiltrate"}]))
        rules = _rules(r)
        self.assertIn("rugpull.tool_changed", rules)
        self.assertIn("rugpull.tool_added", rules)

    def test_empty_baseline_treats_all_as_added(self):
        r = diff_baseline({}, _m([{"name": "a", "description": "x"}]))
        self.assertIn("rugpull.tool_added", _rules(r))

    def test_findings_sorted_by_severity(self):
        bl = build_baseline(_m([{"name": "a", "description": "x"},
                                {"name": "b", "description": "y"}]))
        r = diff_baseline(bl, _m([{"name": "a", "description": "CHANGED"},
                                  {"name": "c", "description": "new"}]))
        sevs = [f.severity for f in r.findings]
        # critical (changed) must come before high (added) before medium (removed)
        self.assertEqual(sevs, sorted(sevs, key={"critical": 0, "high": 1, "medium": 2}.get))


class TestDuplicateNameRegression(unittest.TestCase):
    """BUGFIX: two tools sharing a name must not collapse and hide a rug pull."""

    def test_duplicate_names_both_baselined(self):
        bl = build_baseline(_m([{"name": "dup", "description": "a"},
                                {"name": "dup", "description": "b"}]))
        self.assertIsInstance(bl["tools"]["dup"], list)
        self.assertEqual(len(bl["tools"]["dup"]), 2)

    def test_mutating_one_duplicate_is_caught(self):
        bl = build_baseline(_m([{"name": "dup", "description": "a"},
                                {"name": "dup", "description": "b"}]))
        # attacker mutates the second 'dup' only
        r = diff_baseline(bl, _m([{"name": "dup", "description": "a"},
                                  {"name": "dup", "description": "EVIL"}]))
        self.assertIn("rugpull.tool_changed", _rules(r))
        self.assertTrue(r.failed)

    def test_identical_duplicates_unchanged(self):
        m = _m([{"name": "dup", "description": "a"}, {"name": "dup", "description": "b"}])
        r = diff_baseline(build_baseline(m), m)
        self.assertIn("rugpull.unchanged", _rules(r))

    def test_dropping_one_duplicate_is_a_change(self):
        bl = build_baseline(_m([{"name": "dup", "description": "a"},
                                {"name": "dup", "description": "b"}]))
        r = diff_baseline(bl, _m([{"name": "dup", "description": "a"}]))
        # count went 2 -> 1 for the same name: a mutation, not a clean removal.
        self.assertIn("rugpull.tool_changed", _rules(r))


class TestBackCompat(unittest.TestCase):
    """Older baseline files store a bare hash string; new diff must read them."""

    def test_old_single_string_baseline_unchanged(self):
        m = _m([{"name": "a", "description": "x"}])
        h = _tool_hash({"name": "a", "description": "x"})
        old_baseline = {"server": "srv", "tools": {"a": h}}  # single str, legacy shape
        r = diff_baseline(old_baseline, m)
        self.assertIn("rugpull.unchanged", _rules(r))

    def test_old_single_string_baseline_detects_change(self):
        old_baseline = {"server": "srv", "tools": {"a": "deadbeef" * 8}}
        r = diff_baseline(old_baseline, _m([{"name": "a", "description": "x"}]))
        self.assertIn("rugpull.tool_changed", _rules(r))


class TestNormalizeHashes(unittest.TestCase):
    def test_str_to_counter(self):
        self.assertEqual(dict(_normalize_hashes("abc")), {"abc": 1})

    def test_list_to_counter(self):
        self.assertEqual(dict(_normalize_hashes(["a", "a", "b"])), {"a": 2, "b": 1})

    def test_junk_to_empty(self):
        self.assertEqual(dict(_normalize_hashes(None)), {})
        self.assertEqual(dict(_normalize_hashes(42)), {})


class TestMalformedBaseline(unittest.TestCase):
    def test_non_dict_baseline_raises(self):
        with self.assertRaises(ValueError):
            diff_baseline(["not", "a", "dict"], _m([{"name": "a", "description": "x"}]))

    def test_baseline_with_non_dict_tools_treated_empty(self):
        r = diff_baseline({"server": "x", "tools": "oops"},
                          _m([{"name": "a", "description": "x"}]))
        # tools field junk -> nothing baselined -> the current tool reads as added.
        self.assertIn("rugpull.tool_added", _rules(r))


if __name__ == "__main__":
    unittest.main()
