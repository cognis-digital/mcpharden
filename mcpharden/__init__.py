"""MCPHARDEN — MCP server hardening linter.

Analyzes Model Context Protocol (MCP) server manifests for security
weaknesses across capability declarations, transport configuration, and
tool descriptions. Standard library only, zero install.
"""

from .core import (
    Finding,
    Report,
    audit_manifest,
    load_manifest,
    SEVERITY_ORDER,
)

TOOL_NAME = "mcpharden"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "Report",
    "audit_manifest",
    "load_manifest",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "TOOL_VERSION",
]
