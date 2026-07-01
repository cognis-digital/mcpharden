"""Edge-case tests for the mcpharden CLI (argument parsing, exit codes, formats).

Exercises every subcommand's success and error exit codes, the --fail-on /
--min-severity gates, all output formats (table/json/sarif/html), and the
file-vs-directory + missing-file error paths — through the real main() entry
point so the CLI contract is pinned.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpharden.cli import main  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(REPO_ROOT, "demos")
FIXTURES = os.path.join(DEMOS, "fixtures")


def _fx(*parts):
    return os.path.join(FIXTURES, *parts)


def _write(tmp, obj, name="m.json"):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(obj if isinstance(obj, str) else json.dumps(obj))
    return p


def _run(args):
    """Run main(args), capturing stdout; return (rc, stdout)."""
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(args)
    return rc, out.getvalue()


_CLEAN = {"name": "clean", "transport": {"type": "stdio"},
          "capabilities": {"tools": {}},
          "tools": [{"name": "echo", "description": "Echo back the text payload.",
                     "inputSchema": {"type": "object", "additionalProperties": False}}]}


class TestAuditCommand(unittest.TestCase):
    def test_clean_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, _ = _run(["audit", _write(tmp, _CLEAN)])
            self.assertEqual(rc, 0)

    def test_failing_manifest_returns_1(self):
        rc, _ = _run(["audit", _fx("public-rce-server.json")])
        self.assertEqual(rc, 1)

    def test_missing_file_returns_2(self):
        rc, _ = _run(["audit", "/no/such/file.json"])
        self.assertEqual(rc, 2)

    def test_invalid_json_returns_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, _ = _run(["audit", _write(tmp, "{bad")])
            self.assertEqual(rc, 2)

    def test_json_format_valid(self):
        rc, out = _run(["audit", _fx("hardened-server.json"), "--format", "json"])
        data = json.loads(out)
        self.assertIn("findings", data)
        self.assertEqual(rc, 0)

    def test_sarif_format_valid(self):
        rc, out = _run(["audit", _fx("poisoned-server.json"), "--format", "sarif"])
        data = json.loads(out)
        self.assertEqual(data["version"], "2.1.0")

    def test_html_format(self):
        rc, out = _run(["audit", _fx("poisoned-server.json"), "--format", "html"])
        self.assertIn("<!doctype html>", out.lower())

    def test_min_severity_filters(self):
        rc, out = _run(["audit", _fx("public-rce-server.json"),
                        "--format", "json", "--min-severity", "critical"])
        data = json.loads(out)
        self.assertTrue(all(f["severity"] == "critical" for f in data["findings"]))

    def test_fail_on_low_trips_on_clean_ish(self):
        # hardened server has no findings, so even --fail-on low passes
        rc, _ = _run(["audit", _fx("hardened-server.json"), "--fail-on", "low"])
        self.assertEqual(rc, 0)

    def test_out_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            outp = os.path.join(tmp, "report.json")
            _run(["audit", _fx("hardened-server.json"), "--format", "json", "--out", outp])
            self.assertTrue(os.path.exists(outp))
            with open(outp, encoding="utf-8") as fh:
                json.load(fh)


class TestScanCommand(unittest.TestCase):
    def test_scan_directory(self):
        rc, out = _run(["scan", FIXTURES, "--format", "json"])
        data = json.loads(out)
        self.assertGreater(data["servers_scanned"], 1)

    def test_scan_missing_returns_2(self):
        rc, _ = _run(["scan", "/no/such/dir"])
        self.assertEqual(rc, 2)

    def test_scan_fail_on_high(self):
        rc, _ = _run(["scan", FIXTURES, "--fail-on", "high"])
        self.assertEqual(rc, 1)  # fixtures include failing servers

    def test_scan_table_summary(self):
        rc, out = _run(["scan", _fx("fleet"), "--format", "table"])
        self.assertIn("SCAN SUMMARY", out)


class TestConfigscanCommand(unittest.TestCase):
    def test_configscan_explicit(self):
        rc, out = _run(["configscan", _fx("claude_desktop_config.json"), "--format", "json"])
        data = json.loads(out)
        self.assertTrue(any("config." in f["rule"] for f in data["findings"]))


class TestBaselineDiffCommand(unittest.TestCase):
    def test_baseline_then_diff_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            man = _write(tmp, {"name": "x", "tools": [{"name": "a", "description": "d"}]})
            bl = os.path.join(tmp, "b.json")
            rc, _ = _run(["baseline", man, "-o", bl])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(bl))
            rc, _ = _run(["diff", man, "--baseline", bl])
            self.assertEqual(rc, 0)

    def test_diff_detects_drift_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            man = _write(tmp, {"name": "x", "tools": [{"name": "a", "description": "d"}]}, "m.json")
            bl = os.path.join(tmp, "b.json")
            _run(["baseline", man, "-o", bl])
            mutated = _write(tmp, {"name": "x", "tools": [{"name": "a", "description": "EVIL"}]}, "m2.json")
            rc, _ = _run(["diff", mutated, "--baseline", bl, "--fail-on", "critical"])
            self.assertEqual(rc, 1)

    def test_diff_bad_baseline_returns_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            man = _write(tmp, {"name": "x", "tools": []}, "m.json")
            bad = _write(tmp, "{not json", "bad.json")
            rc, _ = _run(["diff", man, "--baseline", bad])
            self.assertEqual(rc, 2)


class TestPostureCommand(unittest.TestCase):
    def test_posture_json(self):
        rc, out = _run(["posture", _fx("fleet"), "--format", "json"])
        data = json.loads(out)
        self.assertIn("fleet_score", data)
        self.assertIn("grade", data)

    def test_posture_min_grade_fails(self):
        rc, _ = _run(["posture", _fx("fleet"), "--min-grade", "A"])
        self.assertEqual(rc, 1)  # the demo fleet grades F

    def test_posture_missing_returns_2(self):
        rc, _ = _run(["posture", "/no/such/dir"])
        self.assertEqual(rc, 2)


class TestInformationalCommands(unittest.TestCase):
    def test_rules_lists_catalogue(self):
        rc, out = _run(["rules"])
        self.assertEqual(rc, 0)
        self.assertIn("detection rules", out)
        self.assertIn("transport.bind_all", out)
        self.assertIn("config.shell_exec", out)
        self.assertIn("rugpull.tool_changed", out)

    def test_vulndb_full(self):
        rc, out = _run(["vulndb"])
        self.assertEqual(rc, 0)
        self.assertIn("MCP-TP-01", out)

    def test_vulndb_by_cve(self):
        rc, out = _run(["vulndb", "--cve", "CVE-2025-54136"])
        self.assertEqual(rc, 0)
        self.assertIn("MCP-", out)

    def test_vulndb_by_id_json(self):
        rc, out = _run(["vulndb", "--id", "MCP-CI-01", "--format", "json"])
        data = json.loads(out)
        self.assertEqual(data[0]["id"], "MCP-CI-01")

    def test_vulndb_unknown_cve_returns_1(self):
        rc, _ = _run(["vulndb", "--cve", "CVE-9999-00000"])
        self.assertEqual(rc, 1)

    def test_no_command_returns_2(self):
        rc, _ = _run([])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
