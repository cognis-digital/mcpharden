"""Scenario 33 - CI reporting + exfiltration detection.

Two additive capabilities in one scenario:

* JUnit XML export, so a hardening scan renders next to the unit tests in the CI
  run summary (Jenkins/GitLab/GitHub action-junit-report all read it);
* the data-exfiltration surface rule, which fires when a poisoned tool
  description couples reading sensitive local data (.env, secrets, keys) with
  shipping it to an external destination.
"""
from _common import fixture, rule, sev

import xml.etree.ElementTree as ET

from mcpharden import audit_path, scan
from mcpharden.report import to_junit


def main() -> None:
    rule("EXFILTRATION DETECTION + JUNIT REPORT for CI")

    print("\n1) A 'notes helper' whose description hides an egress channel:")
    report = audit_path(fixture("exfil-server.json"))
    for f in report.findings:
        marker = "  <-- exfil" if f.rule == "tool.exfiltration_surface" else ""
        print(f"   [{sev(f.severity)}] {f.rule:<28} {f.message[:60]}{marker}")

    print("\n2) The same scan as a JUnit report your CI can render:\n")
    reports = scan(fixture("exfil-server.json"))
    xml = to_junit(reports, fail_on="high")
    root = ET.fromstring(xml)  # prove it is well-formed
    suite = root.find("testsuite")
    print(f"   <testsuite tests={suite.get('tests')} failures={suite.get('failures')}>")
    for case in root.iter("testcase"):
        verdict = "FAIL" if case.find("failure") is not None else "PASS"
        print(f"     [{verdict}] {case.get('name')}")

    print("\n   Full JUnit XML (first lines):")
    for line in xml.splitlines()[:4]:
        print(f"     {line}")

    print("\nUse `mcpharden scan servers/ --format junit --out report.xml` in CI.")


if __name__ == "__main__":
    main()
