"""End-to-end integration tests across mcpharden's whole surface.

These cross module boundaries the way a real user does: load -> audit -> serialize,
scan a directory -> SARIF, baseline -> mutate -> diff, configscan -> findings,
and the full CLI pipeline (subprocess) for the documented commands. They guard
against regressions that only appear when modules are wired together.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mcpharden  # noqa: E402
from mcpharden import (  # noqa: E402
    audit_path,
    scan,
    scan_to_dict,
    to_sarif,
    to_html,
    build_baseline,
    diff_baseline,
    load_manifest,
    posture,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(REPO_ROOT, "demos", "fixtures")


def _fx(*p):
    return os.path.join(FIXTURES, *p)


def _write(tmp, obj, name="m.json"):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(obj if isinstance(obj, str) else json.dumps(obj))
    return p


class TestPackageSurface(unittest.TestCase):
    def test_version_consistent(self):
        with open(os.path.join(REPO_ROOT, "VERSION"), encoding="utf-8") as fh:
            file_version = fh.read().strip()
        self.assertEqual(mcpharden.__version__, file_version)
        self.assertEqual(mcpharden.TOOL_VERSION, file_version)

    def test_public_api_exports(self):
        for name in ("audit_manifest", "scan", "to_sarif", "to_html",
                     "build_baseline", "diff_baseline", "audit_config",
                     "assess", "vulndb", "PostureReport"):
            self.assertIn(name, mcpharden.__all__, name)
            self.assertTrue(hasattr(mcpharden, name), name)


class TestAuditToSarifPipeline(unittest.TestCase):
    def test_poisoned_to_sarif_each_finding_a_result(self):
        rep = audit_path(_fx("poisoned-server.json"))
        sarif = to_sarif([rep])
        self.assertEqual(len(sarif["runs"][0]["results"]), len(rep.findings))

    def test_scan_directory_to_sarif(self):
        reps = scan(FIXTURES)
        sarif = to_sarif(reps)
        # every distinct rule across the fleet becomes a SARIF rule object
        emitted = {f.rule for r in reps for f in r.findings}
        sarif_rules = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(emitted, sarif_rules)

    def test_scan_directory_to_html(self):
        reps = scan(_fx("fleet"))
        html = to_html(reps)
        self.assertIn("<!doctype html>", html.lower())
        self.assertIn("server(s) scanned", html)


class TestBaselineRoundTripOnFixtures(unittest.TestCase):
    def test_trusted_baseline_matches_itself(self):
        trusted = load_manifest(_fx("payments-trusted.json"))
        bl = build_baseline(trusted)
        r = diff_baseline(bl, trusted)
        self.assertFalse(r.failed)

    def test_rugpull_detected_on_fixtures(self):
        trusted = load_manifest(_fx("payments-trusted.json"))
        bl = build_baseline(trusted)
        rugged = load_manifest(_fx("payments-rugpulled.json"))
        r = diff_baseline(bl, rugged)
        rules = {f.rule for f in r.findings}
        self.assertTrue(r.failed)
        self.assertTrue(rules & {"rugpull.tool_changed", "rugpull.tool_added"})

    def test_baseline_json_persists_and_reloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            trusted = load_manifest(_fx("payments-trusted.json"))
            bl = build_baseline(trusted)
            blpath = os.path.join(tmp, "bl.json")
            with open(blpath, "w", encoding="utf-8") as fh:
                json.dump(bl, fh)
            with open(blpath, encoding="utf-8") as fh:
                reloaded = json.load(fh)
            r = diff_baseline(reloaded, trusted)
            self.assertFalse(r.failed)


class TestScanPostureConsistency(unittest.TestCase):
    def test_posture_server_count_matches_scan(self):
        reps = scan(_fx("fleet"))
        pr = posture.assess(_fx("fleet"))
        self.assertEqual(pr.server_count, len(reps))

    def test_posture_score_is_bounded(self):
        pr = posture.assess(_fx("fleet"))
        self.assertGreaterEqual(pr.fleet_score, 0)
        self.assertLessEqual(pr.fleet_score, 100)


class TestSubprocessCli(unittest.TestCase):
    """The CLI must work through the real `python -m mcpharden` entry point."""

    def _run(self, *args):
        env = dict(os.environ, PYTHONUTF8="1")
        return subprocess.run([sys.executable, "-m", "mcpharden", *args],
                              cwd=REPO_ROOT, capture_output=True, text=True, env=env)

    def test_version_flag(self):
        proc = self._run("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("mcpharden", proc.stdout)

    def test_rules_subcommand(self):
        proc = self._run("rules")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("detection rules", proc.stdout)

    def test_scan_json_failing_exit_1(self):
        proc = self._run("scan", _fx("public-rce-server.json"), "--format", "json",
                         "--fail-on", "critical")
        self.assertEqual(proc.returncode, 1)
        json.loads(proc.stdout)

    def test_posture_table(self):
        proc = self._run("posture", _fx("fleet"))
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Fleet score", proc.stdout)

    def test_vulndb_json(self):
        proc = self._run("vulndb", "--format", "json")
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(json.loads(proc.stdout))


class TestNoNetwork(unittest.TestCase):
    """mcpharden must be fully offline; importing it must not open sockets."""

    def test_audit_works_without_socket(self):
        import socket

        orig = socket.socket

        def _blocked(*a, **k):
            raise AssertionError("mcpharden attempted a network connection")

        socket.socket = _blocked
        try:
            rep = audit_path(_fx("poisoned-server.json"))
            self.assertTrue(rep.findings)
            scan_to_dict(_fx("fleet"))
            posture.assess(_fx("fleet"))
        finally:
            socket.socket = orig


if __name__ == "__main__":
    unittest.main()
