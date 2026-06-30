# Demos

Five runnable scenarios in [`../demos/`](../demos/), each targeting a different
audience. Every scenario runs **fully offline** against the bundled sample
manifests in [`../demos/fixtures/`](../demos/fixtures/), uses the real
`mcpharden` API (no fabricated functions or output), prints narrated output, and
exits 0 — so they double as smoke tests.

```bash
PYTHONUTF8=1 python demos/run_all.py              # all five, end to end
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

---

Each demo prints clear, narrated output and exits 0, so they double as smoke
tests — `tests/test_demos.py` runs every scenario under `pytest`.
