"""Core hardening engine for MCP server manifests.

The linter consumes an MCP server descriptor (the JSON object a server
advertises during initialize / tools-list) and applies a rule set spanning
three domains:

  * transport   — stdio vs http/sse, TLS, bind address, auth
  * capability  — declared capabilities vs. tools actually exposed
  * tooling     — per-tool descriptions, schemas, danger surface

No network access; everything is computed locally from the manifest.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# Severity ordering, highest first. Used for sorting + exit-code policy.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Verbs in a tool name/description that imply a dangerous side effect and
# therefore demand an explicit, non-trivial description + input schema.
_DANGEROUS_VERBS = (
    "delete", "remove", "drop", "destroy", "exec", "execute", "run",
    "shell", "spawn", "write", "update", "patch", "kill", "truncate",
    "deploy", "transfer", "send", "pay", "purchase", "sudo", "eval",
)

# Patterns that look like secrets baked into a manifest.
_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|bearer|authorization)"
    r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-./+]{12,}"
)


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    location: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    source: str
    server_name: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    @property
    def score(self) -> int:
        """0-100 hardening score; critical/high dominate the penalty."""
        weights = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
        penalty = sum(weights[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def failed(self) -> bool:
        c = self.counts
        return c["critical"] > 0 or c["high"] > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "server_name": self.server_name,
            "score": self.score,
            "failed": self.failed,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
        }


class ManifestError(ValueError):
    """Raised when a manifest cannot be parsed or is structurally invalid."""


def load_manifest(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("manifest root must be a JSON object")
    # Stash the raw text so secret-scanning can see formatting/whitespace.
    data.setdefault("_raw_text", raw)
    return data


# --------------------------------------------------------------------------
# Rule implementations
# --------------------------------------------------------------------------

def _check_transport(m: Dict[str, Any], out: List[Finding]) -> None:
    transport = m.get("transport") or {}
    if not isinstance(transport, dict):
        out.append(Finding(
            "transport.malformed", "high",
            "`transport` is present but is not an object.",
            "transport",
            "Declare transport as an object, e.g. {\"type\": \"stdio\"}.",
        ))
        return

    ttype = str(transport.get("type", "")).lower()
    if not ttype:
        out.append(Finding(
            "transport.undeclared", "medium",
            "No transport type declared; clients cannot reason about exposure.",
            "transport.type",
            "Set transport.type to one of stdio, sse, http.",
        ))
        return

    if ttype in ("http", "sse", "streamable-http"):
        host = str(transport.get("host", "")).lower()
        if host in ("0.0.0.0", "::", "*"):
            out.append(Finding(
                "transport.bind_all", "critical",
                f"HTTP transport binds to {host or '0.0.0.0'} (all interfaces); "
                "the MCP server is reachable off-host.",
                "transport.host",
                "Bind to 127.0.0.1 unless remote access is required, and front "
                "with an authenticating reverse proxy.",
            ))
        if not transport.get("tls", False):
            out.append(Finding(
                "transport.no_tls", "high",
                "Network transport without TLS; tool traffic and tokens are "
                "sent in cleartext.",
                "transport.tls",
                "Enable TLS (transport.tls=true) or terminate TLS at a proxy.",
            ))
        if not transport.get("auth"):
            out.append(Finding(
                "transport.no_auth", "high",
                "Network transport without an auth declaration; any client that "
                "reaches the port can invoke tools.",
                "transport.auth",
                "Require a bearer token / OAuth and declare it in transport.auth.",
            ))
        origins = transport.get("allowed_origins")
        if origins in ("*", ["*"]):
            out.append(Finding(
                "transport.wildcard_origin", "medium",
                "Wildcard allowed_origins enables DNS-rebinding / cross-origin "
                "access to the server.",
                "transport.allowed_origins",
                "Pin allowed_origins to explicit, trusted origins.",
            ))
    elif ttype == "stdio":
        pass  # stdio is the least-exposed transport; nothing to flag.
    else:
        out.append(Finding(
            "transport.unknown_type", "low",
            f"Unrecognized transport type '{ttype}'.",
            "transport.type",
            "Use a known transport: stdio, sse, http.",
        ))


def _check_capabilities(m: Dict[str, Any], out: List[Finding]) -> None:
    caps = m.get("capabilities")
    tools = m.get("tools") or []
    if caps is None:
        out.append(Finding(
            "capability.undeclared", "medium",
            "No `capabilities` block; clients cannot gate on advertised features.",
            "capabilities",
            "Declare a capabilities object mirroring what the server exposes.",
        ))
        return
    if not isinstance(caps, dict):
        out.append(Finding(
            "capability.malformed", "high",
            "`capabilities` must be an object.", "capabilities",
            "Use the MCP capabilities object shape.",
        ))
        return

    # Tools exist but capability not advertised — client may refuse or, worse,
    # the server is lying about its surface.
    if tools and "tools" not in caps:
        out.append(Finding(
            "capability.tools_mismatch", "high",
            f"{len(tools)} tool(s) exposed but `capabilities.tools` is not "
            "advertised — capability declaration and surface disagree.",
            "capabilities.tools",
            "Advertise every capability you actually serve.",
        ))
    # Advertised but unused capabilities widen the trust surface needlessly.
    if "tools" in caps and not tools:
        out.append(Finding(
            "capability.tools_empty", "low",
            "Advertises tools capability but exposes zero tools.",
            "capabilities.tools",
            "Drop unused capability advertisements to minimize attack surface.",
        ))
    if caps.get("experimental"):
        out.append(Finding(
            "capability.experimental", "low",
            "Experimental capabilities are enabled.", "capabilities.experimental",
            "Disable experimental capabilities in production deployments.",
        ))


def _check_tools(m: Dict[str, Any], out: List[Finding]) -> None:
    tools = m.get("tools")
    if tools is None:
        return
    if not isinstance(tools, list):
        out.append(Finding(
            "tool.malformed", "high", "`tools` must be an array.", "tools",
            "Express tools as a list of tool objects.",
        ))
        return

    seen: Dict[str, int] = {}
    for idx, tool in enumerate(tools):
        loc = f"tools[{idx}]"
        if not isinstance(tool, dict):
            out.append(Finding(
                "tool.malformed", "high", "Tool entry is not an object.", loc,
                "Each tool must be an object with name + description.",
            ))
            continue
        name = str(tool.get("name", "")).strip()
        if name:
            loc = f"tools[{idx}]:{name}"
            seen[name] = seen.get(name, 0) + 1
        else:
            out.append(Finding(
                "tool.no_name", "high", "Tool has no name.", loc,
                "Give every tool a stable, unique name.",
            ))

        desc = str(tool.get("description", "")).strip()
        if not desc:
            out.append(Finding(
                "tool.no_description", "medium",
                "Tool has no description; agents cannot judge safe usage and "
                "are prone to misuse.",
                loc,
                "Add a clear description stating purpose and side effects.",
            ))
        elif len(desc) < 12:
            out.append(Finding(
                "tool.thin_description", "low",
                f"Tool description is very short ('{desc}').", loc,
                "Describe inputs, outputs, and side effects in full.",
            ))

        # Prompt-injection / instruction-smuggling in descriptions.
        low_desc = desc.lower()
        if any(p in low_desc for p in (
            "ignore previous", "ignore all previous", "system prompt",
            "do not tell", "without informing", "bypass",
        )):
            out.append(Finding(
                "tool.injection_in_description", "critical",
                "Tool description contains instruction-smuggling text that can "
                "hijack the calling agent.",
                loc,
                "Remove imperative/meta instructions from tool descriptions.",
            ))

        schema = tool.get("inputSchema") or tool.get("input_schema")
        haystack = (name + " " + desc).lower()
        dangerous = any(v in haystack for v in _DANGEROUS_VERBS)
        if dangerous:
            if not schema:
                out.append(Finding(
                    "tool.danger_no_schema", "high",
                    "Side-effecting tool exposes no inputSchema; arguments are "
                    "unvalidated and unconstrained.",
                    loc,
                    "Provide a strict JSON Schema (types, enums, required).",
                ))
            if not tool.get("confirm") and not tool.get("requiresConfirmation"):
                out.append(Finding(
                    "tool.danger_no_confirm", "medium",
                    "Side-effecting tool does not request user confirmation.",
                    loc,
                    "Set requiresConfirmation=true for destructive operations.",
                ))

        if isinstance(schema, dict):
            if schema.get("additionalProperties") is True:
                out.append(Finding(
                    "tool.schema_open", "medium",
                    "inputSchema sets additionalProperties=true; unexpected "
                    "fields are accepted.",
                    loc,
                    "Set additionalProperties=false to reject unknown args.",
                ))

    for dup_name, count in seen.items():
        if count > 1:
            out.append(Finding(
                "tool.duplicate_name", "high",
                f"Tool name '{dup_name}' is declared {count} times; clients "
                "cannot disambiguate which implementation runs.",
                f"tools:{dup_name}",
                "Make every tool name unique.",
            ))


def _check_secrets(m: Dict[str, Any], out: List[Finding]) -> None:
    raw = m.get("_raw_text", "")
    if raw and _SECRET_RE.search(raw):
        out.append(Finding(
            "manifest.embedded_secret", "critical",
            "Manifest appears to contain an embedded credential / token.",
            "<manifest>",
            "Move secrets to environment variables or a secret store; never "
            "ship them in the manifest.",
        ))


def audit_manifest(manifest: Dict[str, Any], source: str = "<manifest>") -> Report:
    """Run every rule against a parsed manifest and return a Report."""
    name = str(manifest.get("name") or manifest.get("server_name") or "unknown")
    findings: List[Finding] = []
    _check_transport(manifest, findings)
    _check_capabilities(manifest, findings)
    _check_tools(manifest, findings)
    _check_secrets(manifest, findings)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule))
    return Report(source=source, server_name=name, findings=findings)
