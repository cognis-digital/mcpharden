# Demos

**Twenty** runnable scenarios in [`../demos/`](../demos/), each targeting a
different audience or attack class. Every scenario runs **fully offline** against
the bundled sample manifests in [`../demos/fixtures/`](../demos/fixtures/), uses
the real `mcpharden` API (no fabricated functions or output), prints narrated
output, and exits 0 — so they double as smoke tests (`tests/test_demos.py` runs
all twenty under `pytest`).

```bash
PYTHONUTF8=1 python demos/run_all.py              # all twenty, end to end
PYTHONUTF8=1 python demos/05_red_team_fleet_posture.py   # or just one
```

> On Windows set `PYTHONUTF8=1` so the narrated output (the `…` ellipsis and
> en-dashes) encodes cleanly on the default code page.

## Audience map

| # | Scenario | Audience | API exercised | The point |
|---|----------|----------|---------------|-----------|
| 1 | [`01_ai_platform_review.py`](../demos/01_ai_platform_review.py) | AI platform / security engineers | `audit_path`, `Report.score`, `Report.failed` | Gate every server before it joins the agent trust boundary; fail closed on any critical/high. |
| 2 | [`02_server_author_lint.py`](../demos/02_server_author_lint.py) | MCP server authors | `audit_path`, `Finding.remediation`, `Report.counts` | Lint your own manifest, follow the remediations, watch the score climb 0 → 100. |
| 3 | [`03_auditor_cve_mapping.py`](../demos/03_auditor_cve_mapping.py) | Security auditors / compliance | `audit_path`, `vulndb.BY_RULE`, `to_sarif` | Tie every finding to a named MCP attack class + real CVE, and emit SARIF for code-scanning. |
| 4 | [`04_blue_team_rugpull.py`](../demos/04_blue_team_rugpull.py) | Blue team / incident response | `build_baseline`, `diff_baseline` | Pin what you approved, then catch the silent rug-pull (mutated + added tools). |
| 5 | [`05_red_team_fleet_posture.py`](../demos/05_red_team_fleet_posture.py) | Red team / attack-surface review | `posture.assess`, `PostureReport.grade` | Find the cross-server risks (shared secret, tool collision, lateral movement) a per-server audit can't see. |
| 6 | [`06_compliance_sarif_export.py`](../demos/06_compliance_sarif_export.py) | Compliance / pipeline | `scan`, `to_sarif` | Scan a directory and emit SARIF 2.1.0 for GitHub code-scanning upload. |
| 7 | [`07_client_config_audit.py`](../demos/07_client_config_audit.py) | End users / IT admins | `configaudit.audit_config_path` | Audit the `mcpServers` block you pasted into Claude Desktop / Cursor / VS Code — risky vs hardened. |
| 8 | [`08_malformed_resilience.py`](../demos/08_malformed_resilience.py) | Tooling / robustness | `scan`, `load_manifest`, `ManifestError` | One broken manifest never aborts the scan; bad files degrade to a single finding. |
| 9 | [`09_confused_deputy.py`](../demos/09_confused_deputy.py) | Identity / auth architects | `audit_path`, `vulndb.BY_RULE` | Token passthrough collapses the auth boundary (MCP-TPT-01), even with TLS + OAuth. |
| 10 | [`10_line_jumping.py`](../demos/10_line_jumping.py) | Human reviewers | `audit_path`, `load_manifest` | ANSI/control-char instructions hidden from the eye but ingested by the model (MCP-LJ-01). |
| 11 | [`11_supply_chain_pinning.py`](../demos/11_supply_chain_pinning.py) | Supply-chain / DevSecOps | `audit_manifest` | Unpinned `npx`/`uvx` launch = run the attacker's release (MCP-SC-01); pin to clear it. |
| 12 | [`12_cors_dns_rebinding.py`](../demos/12_cors_dns_rebinding.py) | Network / infra security | `audit_path` | Wildcard CORS + bind-all + no-TLS = a browser-driven DNS-rebinding target (MCP-SSE-01). |
| 13 | [`13_sampling_dos.py`](../demos/13_sampling_dos.py) | FinOps / abuse prevention | `audit_path` | Unbounded sampling is a medium-severity credit-drain a high gate ignores (MCP-SAMP-01). |
| 14 | [`14_oauth_binding.py`](../demos/14_oauth_binding.py) | OAuth / session security | `audit_path` | OAuth without PKCE/state + session id in URL = takeover (MCP-OAUTH-01). |
| 15 | [`15_tool_shadowing.py`](../demos/15_tool_shadowing.py) | Multi-server trust | `audit_path`, `posture.assess` | One server rewriting how you use another's tools (MCP-TS-01) + the name-collision precondition. |
| 16 | [`16_clean_fleet_grade.py`](../demos/16_clean_fleet_grade.py) | Platform owners | `posture.assess` | What "done" looks like: a hardened fleet that grades A with zero correlations. |
| 17 | [`17_duplicate_tool_rugpull.py`](../demos/17_duplicate_tool_rugpull.py) | Blue team (subtle) | `build_baseline`, `diff_baseline` | Mutating one of two same-named tools is still caught (multiset baseline). |
| 18 | [`18_ci_gate_policy.py`](../demos/18_ci_gate_policy.py) | CI/CD engineers | `scan` | Model `--fail-on critical/high/medium` and see which servers each gate admits or blocks. |
| 19 | [`19_wildcard_origin_bugfix.py`](../demos/19_wildcard_origin_bugfix.py) | Detector fidelity | `audit_path`, `audit_manifest` | A wildcard hidden in a list of real origins (`["https://x","*"]`) is now flagged; explicit-only stays clean. |
| 20 | [`20_mcp_server_selfscan.py`](../demos/20_mcp_server_selfscan.py) | Integrators | `mcp_server.handle_request` | mcpharden as an MCP server an agent calls: initialize / tools/list / tools/call over JSON-RPC. |

## 1. AI platform review — *gate every server before it joins the fleet*
**Audience:** AI platform / security engineers.
Audits a hardened server (admit) and two over-broad ones (block — a poisoned
notes server and a world-exposed ops server), then applies the admission policy:
no server with a critical/high finding reaches your agents. This is the
`mcpharden scan --fail-on high` CI gate, in code.

## 2. Server author lint — *fix your manifest before you publish it*
**Audience:** MCP server authors.
Audits an over-broad first draft, walks every finding *with its remediation*,
then audits the hardened rewrite (localhost + TLS + OAuth/PKCE, strict
`inputSchema`s, no shell tool, secrets out of the manifest) and shows the score
move from 0 to 100.

## 3. Auditor CVE mapping — *every finding tied to a class + CVE*
**Audience:** security auditors / compliance.
Audits a poisoned server and maps each finding through `vulndb.BY_RULE` to a
catalog class (e.g. `tool.injection_in_description → MCP-TP-01`,
CVE-2025-54136/-54135), then emits the SARIF 2.1.0 a pipeline attaches to the
build. A finding becomes auditable, not just an alert.

## 4. Blue team rug-pull — *catch tool drift after you trusted it*
**Audience:** blue team / incident response.
Pins a SHA-256 baseline of a payments server when it's trusted, then diffs a
later manifest and catches the mutated `send_payment` (skims transfers) and the
newly-added `export_history` (exfiltrates data) — the CVE-2025-54136 / MCP-RP-01
signature that no point-in-time audit would see.

## 5. Red team fleet posture — *cross-server risks a per-server audit can't see*
**Audience:** red team / attack-surface review.
Correlates a four-server fleet: a credential reused across two servers
(`fleet.shared_secret`), a `read_file` tool-name collision (the shadowing
precondition), an RCE-prone server next to an exposed peer
(`fleet.lateral_movement`), and trust-tier/TLS inconsistency — then rolls it up to
one grade and the single highest-leverage fix.

## 6. Compliance SARIF export — *findings as code-scanning alerts*
**Audience:** compliance / pipeline.
Scans the bundled fleet, emits a SARIF 2.1.0 log, and shows the driver, rule
objects, results, and severity rollup a CI step uploads with
`github/codeql-action/upload-sarif`. Each finding becomes a code-scanning alert
with level, location, and remediation.

## 7. Client config audit — *the servers you actually registered*
**Audience:** end users / IT admins.
Audits a realistic risky Claude Desktop config (unpinned `npx`, a token in `env`,
a `bash -c` server, a cleartext remote, blanket auto-approve), then a hardened
config that passes clean — the before/after an admin applies. `mcpharden
configscan` with no argument auto-detects the real config in place.

## 8. Malformed resilience — *bad files degrade, they don't crash*
**Audience:** tooling / robustness.
Points the scanner at a directory of deliberately broken manifests (invalid JSON,
a JSON array, empty, wrong-typed fields, a half-valid one). `load_manifest`
raises a clear `ManifestError` per file; `scan` turns each into a single
`manifest.unreadable` finding and still audits the rest. One broken file never
blocks the others.

## 9. Confused deputy — *token passthrough collapses the auth boundary*
**Audience:** identity / auth architects.
Audits a proxy server that forwards the user's bearer token downstream
(`auth.token_passthrough` → MCP-TPT-01). Even with TLS + OAuth/PKCE on the
transport, forwarding the token is the finding; the fix is to mint short-lived,
audience-scoped tokens per tool.

## 10. Line jumping — *the instruction your terminal hides from you*
**Audience:** human reviewers.
Audits a calendar server whose `list_events` description carries a concealed
`read ~/.aws/credentials` payload behind ANSI escapes. The demo prints both the
terminal-rendered view and the byte-accurate (escaped) view, and shows
`tool.control_chars` (MCP-LJ-01) catching what the eye can't.

## 11. Supply-chain pinning — *pin the launch command or run the attacker's release*
**Audience:** supply-chain / DevSecOps.
Audits a server launched with unpinned `npx -y weather-mcp-server`
(`transport.unpinned_command` → MCP-SC-01), then audits the same server pinned to
`@1.4.2` and watches the finding clear.

## 12. CORS DNS rebinding — *wildcard CORS turns a browser into your attacker*
**Audience:** network / infra security.
Isolates the network-exposure findings on a public server — bind-all, no-TLS,
no-auth, and wildcard CORS (`transport.cors_wildcard` → MCP-SSE-01) — that
together make it reachable from any web page the victim visits via DNS rebinding.

## 13. Sampling DoS — *the medium-severity finding a high gate ignores*
**Audience:** FinOps / abuse prevention.
Audits a server exposing `sampling` with no rate limit
(`capabilities.sampling_unbounded` → MCP-SAMP-01). It shows the default
`--fail-on high` gate would admit it, while `--fail-on medium` blocks it — the
gate strictness that matters for tools that can spend money.

## 14. OAuth binding — *unbound codes and session ids in URLs*
**Audience:** OAuth / session security.
Audits a server with OAuth but no PKCE/state (`auth.oauth_unbound`) and a session
id in the callback URL (`auth.session_in_url`) — both MCP-OAUTH-01 takeover paths
— and prints the binding fixes.

## 15. Tool shadowing — *one server rewriting how you use another*
**Audience:** multi-server trust.
Audits a helper server whose description tells the agent to route another
server's `read_file` through it (`tool.shadowing` → MCP-TS-01), then runs fleet
posture to surface the shared-name collision that is the structural precondition.

## 16. Clean fleet grade — *what a hardened deployment scores*
**Audience:** platform owners.
The target state: a reference fleet on localhost with TLS + OAuth/PKCE, distinct
scoped credentials, and namespaced tools grades **A** with zero cross-server
correlations. Diff your own fleet against this bar.

## 17. Duplicate-tool rug pull — *mutating one of two same-named tools*
**Audience:** blue team (subtle).
A server can advertise two tools under the same name. The demo baselines a server
with two `search` tools (pinned as a multiset), mutates only the second, and
shows the rug pull is still caught — a regression guard for a real fixed bug.

## 18. CI gate policy — *pick the strictness, fail the build*
**Audience:** CI/CD engineers.
Models the exact `--fail-on` admission logic across three gate strictnesses
(critical / high / medium) and prints which servers each policy admits or blocks,
so a team can choose the gate that matches its risk tolerance.

## 19. Wildcard-origin bugfix — *a wildcard hidden in a list of real origins*
**Audience:** detector fidelity.
A network server can list explicit origins **and** a `"*"` in the same list. The
demo proves `transport.wildcard_origin` now fires on the mixed list
(`["https://x", "*"]`) while an explicit-only list stays clean — no false
positive. (See "Real bugs fixed" in the README.)

## 20. MCP server self-scan — *mcpharden as a tool an agent calls*
**Audience:** integrators.
Drives mcpharden's own stdio JSON-RPC surface in-process — `initialize`,
`tools/list`, `tools/call` for `scan` and `posture` — exactly as Claude Desktop /
Cursor would, and shows the structured findings come back as tool results.

---

Each demo prints clear, narrated output and exits 0, so they double as smoke
tests — `tests/test_demos.py` runs every scenario under `pytest`.
