"""MCPHARDEN — auto-generated detector core."""
from __future__ import annotations
import re, time
from pathlib import Path
from cognis_core import Finding, ScanResult, score

TOOL_NAME = "MCPHARDEN"
TOOL_VERSION = "0.1.0"

PATTERNS = [('MH-CAP-001', 'critical', 3.0, 'MCP_NO_SCOPES', '"capabilities"\\s*:\\s*\\{\\s*\\}', 'Declare explicit scoped capabilities.'), ('MH-NET-001', 'high', 2.5, 'MCP_INSECURE_TRANSPORT', '"transport"\\s*:\\s*"http"', 'Use stdio or HTTPS+auth. Plain HTTP is unsafe.'), ('MH-DESC-001', 'medium', 2.0, 'MCP_VAGUE_TOOL_DESC', '"description"\\s*:\\s*"(do .* things|helper|misc)"', 'Write specific tool descriptions; vague descriptions enable abuse.'), ('MH-AUTH-001', 'critical', 3.0, 'MCP_NO_AUTH', '"auth"\\s*:\\s*(false|"none")', 'Require authentication for remote MCP servers.')]
FILE_GLOBS = ['*.json', '*.toml']

def scan(target: str, **opts) -> ScanResult:
    t0 = time.time()
    result = ScanResult(tool_name=TOOL_NAME, tool_version=TOOL_VERSION, target=str(target))
    p = Path(target)
    files: list[Path] = []
    if p.is_dir():
        for g in FILE_GLOBS:
            files.extend(p.rglob(g))
    elif p.is_file():
        files = [p]
    result.items_scanned = len(files)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rid,sev,w,title,pat,rem in PATTERNS:
            for m in re.finditer(pat, text):
                line = text.count(chr(10), 0, m.start()) + 1
                result.add(Finding(
                    id=rid, severity=sev, weight=w, title=title,
                    description=f"{title}: `{m.group(0)[:80]}`",
                    location=f"{f}:{line}", remediation=rem, category="mcp-hardening",
                ))
    result.composite_score, result.risk_level = score(result.findings)
    result.scan_duration_ms = int((time.time()-t0)*1000)
    return result
