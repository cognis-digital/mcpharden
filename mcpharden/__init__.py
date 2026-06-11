"""mcpharden — MCP server hardening linter. Part of the Cognis Neural Suite."""

from mcpharden.core import (
    TOOL_NAME,
    TOOL_VERSION,
    Finding,
    Report,
    ManifestError,
    SEVERITY_ORDER,
    audit_manifest,
    audit_path,
    load_manifest,
    scan,
    scan_to_dict,
    to_sarif,
    to_html,
)

__version__ = TOOL_VERSION

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "__version__",
    "Finding",
    "Report",
    "ManifestError",
    "SEVERITY_ORDER",
    "audit_manifest",
    "audit_path",
    "load_manifest",
    "scan",
    "scan_to_dict",
    "to_sarif",
    "to_html",
]
