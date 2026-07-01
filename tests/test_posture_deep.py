"""Deep correlator tests for posture using synthetic ServerSummary objects.

These construct ServerSummary instances directly and drive analyze() so each
cross-server correlator (collisions, shared secrets, lateral movement, trust
tiers, TLS, failure concentration) is exercised at its boundary conditions,
independent of fixture files.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpharden import posture  # noqa: E402
from mcpharden.posture import ServerSummary, analyze  # noqa: E402


def _srv(name, *, transport="stdio", network=False, failed=False, score=100,
         rules=(), tools=(), secrets=(), auth=False, tls=False):
    return ServerSummary(
        source=f"{name}.json", name=name, transport_type=transport, network=network,
        failed=failed, score=score, rules=frozenset(rules), tool_names=tuple(tools),
        secrets=tuple(secrets), has_auth=auth, has_tls=tls)


def _rules(pr):
    return {f.rule for f in pr.findings}


class TestCollisionBoundaries(unittest.TestCase):
    def test_no_collision_single_server(self):
        pr = analyze([_srv("a", tools=["read", "write"])])
        self.assertNotIn("fleet.tool_collision", _rules(pr))

    def test_collision_two_servers_same_tool(self):
        pr = analyze([_srv("a", tools=["read"]), _srv("b", tools=["read"])])
        self.assertIn("fleet.tool_collision", _rules(pr))

    def test_no_collision_disjoint_tools(self):
        pr = analyze([_srv("a", tools=["x"]), _srv("b", tools=["y"])])
        self.assertNotIn("fleet.tool_collision", _rules(pr))

    def test_one_collision_per_name(self):
        pr = analyze([_srv("a", tools=["read", "write"]),
                      _srv("b", tools=["read", "write"])])
        cols = [f for f in pr.findings if f.rule == "fleet.tool_collision"]
        self.assertEqual(len(cols), 2)

    def test_three_way_collision_single_finding(self):
        pr = analyze([_srv("a", tools=["read"]), _srv("b", tools=["read"]),
                      _srv("c", tools=["read"])])
        cols = [f for f in pr.findings if f.rule == "fleet.tool_collision"]
        self.assertEqual(len(cols), 1)
        self.assertIn("3 servers", cols[0].message)


class TestSharedSecretBoundaries(unittest.TestCase):
    SECRET = "sk_live_ABCDEFGH1234567890"

    def test_shared_across_two(self):
        pr = analyze([_srv("a", secrets=[self.SECRET]), _srv("b", secrets=[self.SECRET])])
        self.assertIn("fleet.shared_secret", _rules(pr))

    def test_distinct_secrets_no_finding(self):
        pr = analyze([_srv("a", secrets=["sk_live_AAAA1111BBBB2222"]),
                      _srv("b", secrets=["sk_live_CCCC3333DDDD4444"])])
        self.assertNotIn("fleet.shared_secret", _rules(pr))

    def test_single_server_secret_not_shared(self):
        pr = analyze([_srv("a", secrets=[self.SECRET])])
        self.assertNotIn("fleet.shared_secret", _rules(pr))

    def test_secret_never_printed_in_full(self):
        pr = analyze([_srv("a", secrets=[self.SECRET]), _srv("b", secrets=[self.SECRET])])
        for f in pr.findings:
            self.assertNotIn(self.SECRET, f.message)

    def test_shared_secret_is_critical(self):
        pr = analyze([_srv("a", secrets=[self.SECRET]), _srv("b", secrets=[self.SECRET])])
        f = next(f for f in pr.findings if f.rule == "fleet.shared_secret")
        self.assertEqual(f.severity, "critical")


class TestLateralMovement(unittest.TestCase):
    def test_rce_plus_exposed_peer(self):
        pr = analyze([
            _srv("rce", rules=["tool.shell_exec"]),
            _srv("net", transport="http", network=True, rules=["transport.no_auth"]),
        ])
        self.assertIn("fleet.lateral_movement", _rules(pr))

    def test_rce_alone_no_lateral(self):
        pr = analyze([_srv("rce", rules=["tool.shell_exec"])])
        self.assertNotIn("fleet.lateral_movement", _rules(pr))

    def test_exposed_peer_alone_no_lateral(self):
        pr = analyze([_srv("net", transport="http", network=True, rules=["transport.no_auth"])])
        self.assertNotIn("fleet.lateral_movement", _rules(pr))

    def test_unpinned_command_is_rce(self):
        pr = analyze([
            _srv("rce", rules=["transport.unpinned_command"]),
            _srv("net", transport="http", network=True, rules=["transport.bind_all"]),
        ])
        self.assertIn("fleet.lateral_movement", _rules(pr))


class TestTrustTiers(unittest.TestCase):
    def test_auth_inconsistency(self):
        pr = analyze([
            _srv("a", transport="http", network=True, auth=True, tls=True),
            _srv("b", transport="http", network=True, auth=False, tls=True),
        ])
        self.assertIn("fleet.trust_tier_inconsistency", _rules(pr))

    def test_all_authed_clean(self):
        pr = analyze([
            _srv("a", transport="http", network=True, auth=True, tls=True),
            _srv("b", transport="http", network=True, auth=True, tls=True),
        ])
        self.assertNotIn("fleet.trust_tier_inconsistency", _rules(pr))

    def test_single_network_server_no_tier_finding(self):
        pr = analyze([_srv("a", transport="http", network=True, auth=False)])
        self.assertNotIn("fleet.trust_tier_inconsistency", _rules(pr))

    def test_tls_inconsistency(self):
        pr = analyze([
            _srv("a", transport="http", network=True, auth=True, tls=True),
            _srv("b", transport="http", network=True, auth=True, tls=False),
        ])
        self.assertIn("fleet.tls_inconsistency", _rules(pr))

    def test_local_servers_ignored_for_tiers(self):
        pr = analyze([_srv("a", auth=True), _srv("b", auth=False)])
        self.assertNotIn("fleet.trust_tier_inconsistency", _rules(pr))


class TestFailureConcentration(unittest.TestCase):
    def test_majority_failing(self):
        pr = analyze([_srv("a", failed=True, score=40), _srv("b", failed=True, score=30),
                      _srv("c", failed=False, score=90)])
        self.assertIn("fleet.failure_concentration", _rules(pr))

    def test_minority_failing_clean(self):
        pr = analyze([_srv("a", failed=True, score=40), _srv("b", failed=False),
                      _srv("c", failed=False)])
        self.assertNotIn("fleet.failure_concentration", _rules(pr))

    def test_single_failure_not_concentration(self):
        pr = analyze([_srv("a", failed=True, score=40), _srv("b", failed=False)])
        self.assertNotIn("fleet.failure_concentration", _rules(pr))


class TestFleetScoreGrade(unittest.TestCase):
    def test_empty_fleet_grade_a(self):
        pr = analyze([])
        self.assertEqual(pr.grade, "A")
        self.assertEqual(pr.fleet_score, 100)

    def test_all_clean_grade_a(self):
        pr = analyze([_srv("a", score=100), _srv("b", score=100)])
        self.assertEqual(pr.grade, "A")

    def test_correlations_drop_grade(self):
        pr = analyze([_srv("a", score=100, secrets=["sk_live_SHARED1234567890"]),
                      _srv("b", score=100, secrets=["sk_live_SHARED1234567890"])])
        self.assertLess(pr.fleet_score, 100)

    def test_score_never_negative(self):
        servers = [_srv(f"s{i}", failed=True, score=0,
                        rules=["tool.shell_exec"], secrets=["sk_live_X1234567890ABC"],
                        transport="http", network=True) for i in range(6)]
        self.assertGreaterEqual(analyze(servers).fleet_score, 0)

    def test_grade_letters(self):
        # synthesize fleets whose mean score lands in each band, no correlations
        for score, grade in [(95, "A"), (85, "B"), (72, "C"), (60, "D"), (20, "F")]:
            pr = analyze([_srv("a", score=score)])
            self.assertEqual(pr.grade, grade, f"score {score}")

    def test_top_remediation_is_worst(self):
        pr = analyze([_srv("a", secrets=["sk_live_SHARED1234567890"]),
                      _srv("b", secrets=["sk_live_SHARED1234567890"])])
        self.assertIsNotNone(pr.top_remediation)

    def test_top_remediation_none_when_clean(self):
        self.assertIsNone(analyze([_srv("a")]).top_remediation)


class TestRenderers(unittest.TestCase):
    def test_table_contains_grade(self):
        txt = posture.render_table(analyze([_srv("a", score=100)]))
        self.assertIn("grade A", txt)

    def test_html_escapes_name(self):
        html = posture.render_html(analyze([_srv("<b>x</b>", score=100)]))
        self.assertIn("&lt;b&gt;", html)

    def test_to_dict_json_safe(self):
        import json
        json.dumps(analyze([_srv("a", secrets=["sk_live_SHARED1234567890"]),
                            _srv("b", secrets=["sk_live_SHARED1234567890"])]).to_dict())


if __name__ == "__main__":
    unittest.main()
