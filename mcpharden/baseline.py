"""Tool-definition baselining — detect MCP "rug pulls".

A rug pull (CVE-2025-54136 / MCP-RP-01) is when an approved server silently
changes a tool's behavior or description *after* you trusted it. mcpharden can
pin a baseline of each tool's definition (a hash of name + description +
inputSchema), then diff a later manifest against it and flag anything that was
added, removed, or mutated — the rug-pull signature.

    mcpharden baseline server.json -o server.baseline.json   # pin (once, when trusted)
    mcpharden diff server.json --baseline server.baseline.json   # later: detect drift
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Dict, List, Union

from .core import Finding, Report, SEVERITY_ORDER

# A baselined tool name maps to either a single hash (str) or, when several
# tools share that name, a list of hashes — see ``_normalize_hashes``.
HashEntry = Union[str, List[str]]


def _tool_hash(tool: Dict[str, Any]) -> str:
    basis = {
        "name": tool.get("name", ""),
        "description": tool.get("description", ""),
        "inputSchema": tool.get("inputSchema") or tool.get("input_schema") or {},
    }
    blob = json.dumps(basis, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _normalize_hashes(entry: HashEntry) -> Counter:
    """Coerce a baseline ``tools`` value into a multiset of hashes.

    Two tools can legitimately share a name (the manifest is malformed but the
    server still advertises both). An older single-hash value and the newer
    list-of-hashes value both normalize here, so a rug pull that mutates *one*
    of several same-named tools is still caught — the historical bug was that a
    dict keyed by name silently dropped all but the last duplicate.
    """
    if isinstance(entry, str):
        return Counter([entry])
    if isinstance(entry, list):
        return Counter(str(h) for h in entry)
    return Counter()


def build_baseline(manifest: Dict[str, Any]) -> Dict[str, Any]:
    tools = manifest.get("tools") if isinstance(manifest.get("tools"), list) else []
    grouped: Dict[str, List[str]] = {}
    for i, t in enumerate(tools):
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", f"tool{i}"))
        grouped.setdefault(name, []).append(_tool_hash(t))
    # Single hash stays a bare string (back-compatible with older baselines);
    # only genuine duplicates expand to a list.
    pinned: Dict[str, HashEntry] = {
        name: (hashes[0] if len(hashes) == 1 else hashes)
        for name, hashes in grouped.items()
    }
    return {
        "server": str(manifest.get("name") or manifest.get("server_name") or "unknown"),
        "tools": pinned,
    }


def _baseline_tool_count(base_tools: Dict[str, HashEntry]) -> int:
    return sum(sum(_normalize_hashes(v).values()) for v in base_tools.values())


def diff_baseline(baseline: Dict[str, Any], manifest: Dict[str, Any],
                  source: str = "<manifest>") -> Report:
    if not isinstance(baseline, dict):
        raise ValueError("baseline must be a JSON object written by `build_baseline`")
    raw_tools = baseline.get("tools", {})
    base_tools: Dict[str, HashEntry] = dict(raw_tools) if isinstance(raw_tools, dict) else {}
    current = build_baseline(manifest)["tools"]
    findings: List[Finding] = []

    for name, entry in current.items():
        cur = _normalize_hashes(entry)
        if name not in base_tools:
            findings.append(Finding(
                "rugpull.tool_added", "high",
                f"Tool '{name}' was added since the baseline — it was never reviewed/approved.",
                f"tools:{name}",
                "Re-review the new tool's description and schema before trusting the server."))
            continue
        base = _normalize_hashes(base_tools[name])
        if cur != base:
            # Anything that isn't an exact multiset match is a mutation: a
            # changed hash, or a changed count among same-named duplicates.
            findings.append(Finding(
                "rugpull.tool_changed", "critical",
                f"Tool '{name}' changed since the baseline (description/schema mutated) — "
                "classic rug-pull / tool-poisoning vector.",
                f"tools:{name}",
                "Inspect the diff; do not auto-trust. Re-pin only after review."))
    for name in base_tools:
        if name not in current:
            findings.append(Finding(
                "rugpull.tool_removed", "medium",
                f"Tool '{name}' present in the baseline is gone — server surface changed.",
                f"tools:{name}", "Confirm the removal is expected."))

    if not findings:
        findings.append(Finding(
            "rugpull.unchanged", "info",
            f"All {_baseline_tool_count(base_tools)} baselined tool definition(s) match — no drift.",
            source, ""))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule))
    return Report(source=source, server_name=str(baseline.get("server", "unknown")),
                  findings=findings)
