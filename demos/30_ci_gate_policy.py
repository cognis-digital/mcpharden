"""Scenario 30 - platform/CI engineer: gate every MCP server on a policy.

`--fail-on` gives one severity threshold; a real CI gate needs more: cap the
count of findings at each severity, require a minimum hardening score, forbid
specific rules outright, and record reviewed exceptions (waivers). `mcpharden
ci` reads a `.mcpharden.yml` policy and fails the build accordingly. This demo
runs the same policy against a clean fleet (passes) and a risky server (fails),
printing the exact policy violations.
"""
from _common import fixture, rule, REPO_ROOT

import os

from mcpharden import scan
from mcpharden.policy import evaluate, load_policy


def _run(target: str, policy) -> None:
    reports = scan(target)
    result = evaluate(reports, policy)
    c = result.stats["counts"]
    print(f"\n  target: {os.path.relpath(target, REPO_ROOT)}")
    print(f"  servers={result.stats['servers']}  critical={c['critical']} "
          f"high={c['high']} medium={c['medium']}")
    if result.waived:
        print(f"  waived: {', '.join(sorted(set(result.waived)))}")
    if result.violations:
        print("  POLICY VIOLATIONS:")
        for v in result.violations:
            print(f"    - {v}")
    print(f"  RESULT: {'PASS' if result.passed else 'FAIL'}")


def main() -> None:
    rule("CI GATE  -  fail the build on a hardening policy, not a single flag")
    policy = load_policy(fixture(".mcpharden.yml"))
    print("\nPolicy (.mcpharden.yml):")
    for k, v in policy.to_dict().items():
        if v not in (None, [], set()):
            print(f"     {k}: {v}")

    print("\n1) A clean, well-scoped fleet:")
    _run(fixture("registry-fleet"), policy)

    print("\n2) A risky server (bind-all HTTP + shell-exec tool):")
    _run(fixture("public-rce-server.json"), policy)

    print("\nDrop .mcpharden.yml in your repo and run `mcpharden ci .` in CI;")
    print("a policy violation exits non-zero and blocks the merge.")


if __name__ == "__main__":
    main()
