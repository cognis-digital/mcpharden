"""Scenario 6 - compliance / pipeline integration.

A security pipeline doesn't read tables — it ingests SARIF. This demo scans a
directory of manifests, emits the SARIF 2.1.0 a CI step uploads to GitHub
code-scanning, and shows the rule + result structure the dashboard renders, so
findings land as code-scanning alerts with severities and remediations.
"""
import json

from _common import fixture, rule

from mcpharden import scan, to_sarif


def main() -> None:
    rule("COMPLIANCE  -  scan a directory and emit SARIF for code-scanning")

    reports = scan(fixture("fleet"))
    sarif = to_sarif(reports)
    driver = sarif["runs"][0]["tool"]["driver"]
    results = sarif["runs"][0]["results"]

    print(f"\nScanned {len(reports)} manifest(s) -> SARIF {sarif['version']}")
    print(f"  driver        : {driver['name']} {driver['version']}")
    print(f"  rule objects  : {len(driver['rules'])}")
    print(f"  results       : {len(results)}\n")

    print("Severity rollup (SARIF level + security-severity):")
    by_level = {}
    for res in results:
        by_level.setdefault(res["level"], 0)
        by_level[res["level"]] += 1
    for level, n in sorted(by_level.items()):
        print(f"   {level:<8} {n}")

    print("\nFirst three results as code-scanning alerts:")
    for res in results[:3]:
        loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        print(f"   [{res['level']:<7}] {res['ruleId']:<28} {loc}")

    print("\nWire `mcpharden scan <dir> --format sarif --out mcp.sarif` into CI and")
    print("upload mcp.sarif with github/codeql-action/upload-sarif. Findings become")
    print("code-scanning alerts with severity, location, and remediation.")


if __name__ == "__main__":
    main()
