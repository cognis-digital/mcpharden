"""Robustness / fuzz-style tests: odd-but-survivable manifests must not crash.

audit_manifest is the single entry every path funnels through (CLI, MCP server,
scan, posture). It must never raise on structurally weird input — it should
return a Report (possibly with malformed findings). These tests throw a wide
variety of degenerate manifests at it and assert "returns a Report, no
exception", plus a handful of targeted degenerate-shape findings.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpharden import Report, audit_manifest, to_sarif, to_html  # noqa: E402


def _rules(m):
    return {f.rule for f in audit_manifest(m).findings}


# A broad table of degenerate-but-not-crashing manifests.
_WEIRD_MANIFESTS = [
    {},
    {"name": ""},
    {"name": None},
    {"name": 123},
    {"name": {"nested": "object"}},
    {"transport": None},
    {"transport": {}},
    {"transport": {"type": None}},
    {"transport": {"type": 5}},
    {"transport": {"type": "http", "host": None}},
    {"transport": {"type": "http", "port": "not-a-number"}},
    {"transport": {"type": "http", "tls": "yes"}},
    {"transport": {"type": "http", "auth": []}},
    {"transport": {"type": "http", "allowed_origins": {}}},
    {"capabilities": None},
    {"capabilities": 0},
    {"capabilities": {"tools": None}},
    {"capabilities": {"tools": "yes"}},
    {"tools": None},
    {"tools": []},
    {"tools": [None]},
    {"tools": [{}]},
    {"tools": [{"name": None}]},
    {"tools": [{"name": "", "description": None}]},
    {"tools": [{"name": "t", "inputSchema": "not-a-dict"}]},
    {"tools": [{"name": "t", "description": 42}]},
    {"tools": [[], {}, "string", 1]},
    {"auth": None},
    {"auth": "passthrough"},
    {"auth": []},
    {"capabilities": {"sampling": None}},
    {"dynamicRegistration": "true"},
    {"auto_approve": "yes"},
    {"name": "x", "tools": [{"name": "t", "description": "d", "command": None}]},
    {"transport": {"type": "http", "cors": []}},
    {"transport": {"type": "http", "cors": {"allow_origins": None}}},
]


class TestNeverCrashes(unittest.TestCase):
    def test_all_weird_manifests_return_report(self):
        for i, m in enumerate(_WEIRD_MANIFESTS):
            with self.subTest(index=i, manifest=m):
                report = audit_manifest(m)
                self.assertIsInstance(report, Report)

    def test_weird_manifests_serialize(self):
        for i, m in enumerate(_WEIRD_MANIFESTS):
            with self.subTest(index=i):
                rep = audit_manifest(m)
                # all three serializers must survive the findings
                rep.to_dict()
                to_sarif([rep])
                to_html([rep])

    def test_score_always_in_range(self):
        for m in _WEIRD_MANIFESTS:
            score = audit_manifest(m).score
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)

    def test_counts_keys_stable(self):
        for m in _WEIRD_MANIFESTS:
            c = audit_manifest(m).counts
            self.assertEqual(set(c), {"critical", "high", "medium", "low", "info"})


class TestDegenerateShapesFlagged(unittest.TestCase):
    def test_transport_number_malformed(self):
        self.assertIn("transport.malformed", _rules({"transport": 5}))

    def test_capabilities_list_malformed(self):
        self.assertIn("capability.malformed", _rules({"capabilities": ["x"]}))

    def test_tools_string_malformed(self):
        self.assertIn("tool.malformed", _rules({"tools": "x"}))

    def test_tool_none_entry_malformed(self):
        self.assertIn("tool.malformed", _rules({"capabilities": {"tools": {}},
                                                "tools": [None]}))

    def test_unnamed_tool_no_name(self):
        self.assertIn("tool.no_name", _rules({"capabilities": {"tools": {}},
                                              "tools": [{"description": "something here"}]}))


class TestLargeManifest(unittest.TestCase):
    def test_many_tools(self):
        tools = [{"name": f"tool_{i}", "description": f"Read item number {i} safely."}
                 for i in range(500)]
        m = {"name": "big", "transport": {"type": "stdio"},
             "capabilities": {"tools": {}}, "tools": tools}
        report = audit_manifest(m)
        self.assertIsInstance(report, Report)
        # 500 unique names -> no duplicate findings
        self.assertNotIn("tool.duplicate_name", {f.rule for f in report.findings})

    def test_many_duplicate_tools_one_finding_each(self):
        tools = [{"name": "same", "description": f"impl {i} of the thing"} for i in range(50)]
        m = {"name": "big", "transport": {"type": "stdio"},
             "capabilities": {"tools": {}}, "tools": tools}
        dups = [f for f in audit_manifest(m).findings if f.rule == "tool.duplicate_name"]
        self.assertEqual(len(dups), 1)


class TestUnicodeAndEncoding(unittest.TestCase):
    def test_unicode_tool_name_and_desc(self):
        m = {"name": "café-mcp", "transport": {"type": "stdio"},
             "capabilities": {"tools": {}},
             "tools": [{"name": "café_söka", "description": "Sök i dökümenten på svenska 한국어."}]}
        report = audit_manifest(m)
        html = to_html([report])
        self.assertIn("café", html)

    def test_emoji_in_description(self):
        m = {"name": "x", "transport": {"type": "stdio"}, "capabilities": {"tools": {}},
             "tools": [{"name": "t", "description": "A safe read tool 🔒 with details."}]}
        self.assertIsInstance(audit_manifest(m), Report)


if __name__ == "__main__":
    unittest.main()
