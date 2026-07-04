"""Policy-driven CI gate for mcpharden.

``mcpharden scan`` already supports ``--fail-on``, but a real CI gate needs more
than a single severity threshold: a team wants to cap the *number* of findings
at each severity, require a minimum hardening score, forbid specific rules
outright, and record reviewed-and-accepted exceptions (waivers) so a known,
tracked finding does not break the build forever.

This module defines that policy as data and evaluates a set of scan
:class:`~mcpharden.core.Report` objects against it, returning a structured
:class:`GateResult`. It is consumed by the ``mcpharden ci`` subcommand.

The policy file is JSON (``.mcpharden.json``) or a *flat* YAML subset
(``.mcpharden.yml``) parsed by a tiny built-in reader — no third-party YAML
dependency, so the tool stays standard-library only. Everything is offline and
deterministic.

Example ``.mcpharden.yml``::

    min_score: 80
    max_critical: 0
    max_high: 2
    forbid_rules: tool.shell_exec, transport.bind_all
    waivers: tool.danger_no_confirm, capability.experimental
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .core import Report, SEVERITY_ORDER

__all__ = [
    "Policy",
    "GateResult",
    "DEFAULT_POLICY_NAMES",
    "load_policy",
    "parse_policy",
    "evaluate",
]

DEFAULT_POLICY_NAMES = (
    ".mcpharden.yml", ".mcpharden.yaml", ".mcpharden.json", "mcpharden.policy.json",
)

_GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


@dataclass
class Policy:
    """A CI hardening policy. Any field left ``None`` imposes no constraint."""

    min_score: Optional[int] = None            # min per-server hardening score
    min_grade: Optional[str] = None            # min fleet grade (A..F), needs posture
    max_critical: Optional[int] = None         # cap on total critical findings
    max_high: Optional[int] = None
    max_medium: Optional[int] = None
    max_low: Optional[int] = None
    fail_on: Optional[str] = None              # severity floor (as in --fail-on)
    forbid_rules: Set[str] = field(default_factory=set)   # rules that must never appear
    require_rules: Set[str] = field(default_factory=set)  # rules that MUST appear (e.g. rugpull.unchanged)
    waivers: Set[str] = field(default_factory=set)        # rules excused from all caps/gates

    def to_dict(self) -> Dict[str, Any]:
        return {
            "min_score": self.min_score,
            "min_grade": self.min_grade,
            "max_critical": self.max_critical,
            "max_high": self.max_high,
            "max_medium": self.max_medium,
            "max_low": self.max_low,
            "fail_on": self.fail_on,
            "forbid_rules": sorted(self.forbid_rules),
            "require_rules": sorted(self.require_rules),
            "waivers": sorted(self.waivers),
        }


@dataclass
class GateResult:
    """Outcome of evaluating reports against a policy."""

    passed: bool
    violations: List[str] = field(default_factory=list)
    waived: List[str] = field(default_factory=list)   # rule ids suppressed by a waiver
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": self.violations,
            "waived": sorted(set(self.waived)),
            "stats": self.stats,
        }


# --------------------------------------------------------------------------
# Loading / parsing
# --------------------------------------------------------------------------

def _coerce_set(value: Any) -> Set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {p.strip() for p in value.replace(",", "\n").splitlines() if p.strip()}
    if isinstance(value, (list, tuple, set)):
        return {str(v).strip() for v in value if str(v).strip()}
    return set()


def _coerce_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_policy(data: Dict[str, Any]) -> Policy:
    """Build a :class:`Policy` from a parsed dict (JSON or flat-YAML)."""
    if not isinstance(data, dict):
        raise ValueError("policy must be a mapping of settings")
    grade = data.get("min_grade")
    grade = str(grade).strip().upper() if grade else None
    if grade and grade not in _GRADE_ORDER:
        raise ValueError(f"min_grade must be one of A-F, got {grade!r}")
    fail_on = data.get("fail_on")
    fail_on = str(fail_on).strip().lower() if fail_on else None
    if fail_on and fail_on not in SEVERITY_ORDER:
        raise ValueError(f"fail_on must be a severity, got {fail_on!r}")
    return Policy(
        min_score=_coerce_int(data.get("min_score")),
        min_grade=grade,
        max_critical=_coerce_int(data.get("max_critical")),
        max_high=_coerce_int(data.get("max_high")),
        max_medium=_coerce_int(data.get("max_medium")),
        max_low=_coerce_int(data.get("max_low")),
        fail_on=fail_on,
        forbid_rules=_coerce_set(data.get("forbid_rules")),
        require_rules=_coerce_set(data.get("require_rules")),
        waivers=_coerce_set(data.get("waivers")),
    )


def _parse_flat_yaml(text: str) -> Dict[str, Any]:
    """Parse a *flat* ``key: value`` YAML subset (no nesting, no anchors).

    Supports ``#`` comments, ``key: value`` scalars, and inline lists both as
    comma-separated scalars and as ``[a, b, c]``. This covers every field a
    mcpharden policy needs without pulling in PyYAML.
    """
    out: Dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip() or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if val.startswith("[") and val.endswith("]"):
            val = val[1:-1]
            out[key] = [v.strip().strip("'\"") for v in val.split(",") if v.strip()]
        elif val == "":
            out[key] = None
        else:
            out[key] = val.strip("'\"")
    return out


def load_policy(path: str) -> Policy:
    """Load a policy file (``.json`` parsed as JSON, otherwise flat-YAML)."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if not text.strip():
        raise ValueError(f"policy file {path} is empty")
    if path.lower().endswith(".json"):
        data = json.loads(text)
    else:
        # try JSON first (a .yml that is actually JSON still works), then flat-YAML
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = _parse_flat_yaml(text)
    return parse_policy(data)


def discover_policy(start: str = ".") -> Optional[str]:
    """Return the first known policy file found in ``start`` (or None)."""
    for name in DEFAULT_POLICY_NAMES:
        candidate = os.path.join(start, name)
        if os.path.isfile(candidate):
            return candidate
    return None


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def evaluate(reports: List[Report], policy: Policy,
             fleet_grade: Optional[str] = None) -> GateResult:
    """Evaluate scan reports against a policy.

    Findings whose rule is in ``policy.waivers`` are excluded from severity
    caps and the ``fail_on`` floor (but still reported as ``waived``). Score,
    forbid/require, and grade checks run against the full report.
    """
    waived: List[str] = []
    counts = {k: 0 for k in SEVERITY_ORDER}
    present_rules: Set[str] = set()
    for r in reports:
        for f in r.findings:
            present_rules.add(f.rule)
            if f.rule in policy.waivers:
                waived.append(f.rule)
                continue
            counts[f.severity] += 1

    violations: List[str] = []

    cap_map = [
        ("critical", policy.max_critical),
        ("high", policy.max_high),
        ("medium", policy.max_medium),
        ("low", policy.max_low),
    ]
    for sev, cap in cap_map:
        if cap is not None and counts[sev] > cap:
            violations.append(
                f"{counts[sev]} {sev} finding(s) exceed max_{sev}={cap}")

    if policy.fail_on:
        threshold = SEVERITY_ORDER[policy.fail_on]
        offending = sum(
            1 for r in reports for f in r.findings
            if f.rule not in policy.waivers
            and SEVERITY_ORDER.get(f.severity, 99) <= threshold)
        if offending:
            violations.append(
                f"{offending} finding(s) at/above fail_on={policy.fail_on}")

    if policy.min_score is not None:
        worst = min((r.score for r in reports), default=100)
        if worst < policy.min_score:
            violations.append(
                f"lowest server score {worst} is below min_score={policy.min_score}")

    for rule in sorted(policy.forbid_rules):
        if rule in present_rules:
            violations.append(f"forbidden rule present: {rule}")

    for rule in sorted(policy.require_rules):
        if rule not in present_rules:
            violations.append(f"required rule missing: {rule}")

    if policy.min_grade is not None and fleet_grade is not None:
        if _GRADE_ORDER.get(fleet_grade, 4) > _GRADE_ORDER[policy.min_grade]:
            violations.append(
                f"fleet grade {fleet_grade} is below min_grade={policy.min_grade}")

    stats = {
        "servers": len(reports),
        "counts": counts,
        "waived_count": len(waived),
        "fleet_grade": fleet_grade,
    }
    return GateResult(passed=not violations, violations=violations,
                      waived=waived, stats=stats)
