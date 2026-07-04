"""Fleet baseline registry — rug-pull detection across a whole deployment.

``mcpharden baseline`` / ``diff`` pin and check *one* server. A real agent host
trusts a *fleet* of servers, and any one of them can rug-pull independently.
This module pins every server in a directory into a single registry file, then
verifies a later snapshot of the fleet against it in one pass — reporting, per
server: unchanged, drifted (a tool mutated → rug pull), tools added/removed, a
server that vanished, and a server that newly appeared (never reviewed).

The registry can be HMAC-signed (reusing :mod:`mcpharden.report`) so its
integrity is verifiable: an attacker who tampers with the pinned baselines to
hide a rug pull invalidates the signature.

Standard library only, fully offline, deterministic output.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .baseline import build_baseline, diff_baseline
from .core import (
    Finding,
    ManifestError,
    Report,
    SEVERITY_ORDER,
    TOOL_NAME,
    TOOL_VERSION,
    load_manifest,
    _iter_manifest_files,
)
from .report import sign_attestation, verify_attestation

__all__ = [
    "build_registry",
    "verify_registry",
    "load_registry",
    "sign_registry",
    "is_signed",
]

_REGISTRY_TYPE = "https://cognis.digital/mcpharden/fleet-registry/v1"


def _server_key(manifest: Dict[str, Any], path: str) -> str:
    """Stable identity for a server in the registry: its declared name, or the
    file basename if unnamed. Names win so a server can move files without
    breaking its baseline."""
    name = str(manifest.get("name") or manifest.get("server_name") or "").strip()
    return name or os.path.basename(path)


def build_registry(target: str) -> Dict[str, Any]:
    """Pin every manifest under ``target`` into one registry document.

    Each entry maps a server key to the baseline produced by
    :func:`mcpharden.baseline.build_baseline`. Unreadable manifests are recorded
    with an ``error`` marker rather than aborting the whole pin.
    """
    entries: Dict[str, Any] = {}
    for path in _iter_manifest_files(target):
        try:
            manifest = load_manifest(path)
        except (OSError, ManifestError) as exc:
            entries[os.path.basename(path)] = {"error": str(exc), "source": path}
            continue
        key = _server_key(manifest, path)
        base = build_baseline(manifest)
        entries[key] = {
            "source": path.replace(os.sep, "/"),
            "server": base["server"],
            "tools": base["tools"],
        }
    return {
        "_type": _REGISTRY_TYPE,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "server_count": sum(1 for v in entries.values() if "error" not in v),
        "servers": entries,
    }


def sign_registry(registry: Dict[str, Any], key: str) -> Dict[str, Any]:
    """HMAC-sign a registry document (reuses the attestation envelope)."""
    return sign_attestation(registry, key)


def is_signed(doc: Dict[str, Any]) -> bool:
    return isinstance(doc, dict) and "statement" in doc and "signatures" in doc


def load_registry(path: str, key: Optional[str] = None) -> Dict[str, Any]:
    """Load a registry file. If signed, ``key`` is required and verified.

    Raises ``ValueError`` on a bad signature or a missing key for a signed
    registry, so a tampered registry cannot silently pass verification.
    """
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if is_signed(doc):
        if not key:
            raise ValueError("registry is signed; a --key is required to verify it")
        if not verify_attestation(doc, key):
            raise ValueError("registry signature is INVALID — the file was tampered with")
        return doc["statement"]
    return doc


def verify_registry(registry: Dict[str, Any], target: str) -> List[Report]:
    """Diff a live fleet at ``target`` against a pinned registry.

    Returns one :class:`Report` per server key seen in either the registry or
    the live fleet:

    * matching servers → the per-server rug-pull diff (unchanged / drift /
      added / removed tools);
    * a registry server missing from the live fleet → ``fleet.server_missing``;
    * a live server absent from the registry → ``fleet.server_unregistered``
      (it was never reviewed/pinned).
    """
    servers = registry.get("servers", {})
    if not isinstance(servers, dict):
        raise ValueError("registry has no 'servers' mapping")

    # Index the live fleet by the same server key rule.
    live: Dict[str, Dict[str, Any]] = {}
    live_sources: Dict[str, str] = {}
    for path in _iter_manifest_files(target):
        try:
            manifest = load_manifest(path)
        except (OSError, ManifestError):
            continue
        key = _server_key(manifest, path)
        live[key] = manifest
        live_sources[key] = path

    reports: List[Report] = []
    for key in sorted(set(servers) | set(live)):
        pinned = servers.get(key)
        if pinned is not None and "error" in pinned:
            continue  # entry that failed to pin; nothing to compare
        if key in servers and key in live:
            baseline = {"server": pinned.get("server", key),
                        "tools": pinned.get("tools", {})}
            reports.append(diff_baseline(baseline, live[key], source=live_sources[key]))
        elif key in servers:
            reports.append(Report(
                source=pinned.get("source", key), server_name=key,
                findings=[Finding(
                    "fleet.server_missing", "medium",
                    f"Server '{key}' is pinned in the registry but absent from the "
                    "live fleet — it was removed or renamed.",
                    key,
                    "Confirm the removal is intentional; re-pin the registry if so.")]))
        else:  # key in live only
            reports.append(Report(
                source=live_sources[key], server_name=key,
                findings=[Finding(
                    "fleet.server_unregistered", "high",
                    f"Server '{key}' is present in the live fleet but was never "
                    "pinned in the registry — an unreviewed server joined the "
                    "trust boundary.",
                    key,
                    "Review the new server and add it to the registry before trusting it.")]))
    for r in reports:
        r.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule))
    return reports
