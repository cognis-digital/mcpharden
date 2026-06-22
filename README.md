# MCPHARDEN — MCP server hardening linter — capability declarations, transport, tool descriptions

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ai-security`

[![PyPI](https://img.shields.io/pypi/v/cognis-mcpharden.svg)](https://pypi.org/project/cognis-mcpharden/)
[![CI](https://github.com/cognis-digital/mcpharden/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/mcpharden/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**MCP server hardening linter — capability declarations, transport, tool descriptions.**

*AI Security & Governance — securing LLMs, agents, and the MCP supply chain.*

## Usage — step by step

1. **Install** the linter:
   ```bash
   pip install cognis-mcpharden
   ```
2. **Audit a single MCP server manifest** — `audit` takes a manifest path and prints a findings table:
   ```bash
   mcpharden audit path/to/mcp-server.json
   ```
3. **Scan a directory** of manifests and gate on severity. `scan` walks a file or directory; `--min-severity` filters the report and `--fail-on` controls the exit code:
   ```bash
   mcpharden scan demos/ --min-severity low --fail-on high
   ```
4. **Read the output** in a machine format. `--format` accepts `table` (default), `json`, `sarif`, or `html`; `--out` writes to a file instead of stdout:
   ```bash
   mcpharden scan demos/ --format sarif --out mcpharden.sarif
   # exit code is non-zero when a finding >= --fail-on is present
   echo $?
   ```
   List the detection rules behind those findings with `mcpharden rules`.
5. **Automate in CI** — fail the build on high-severity findings and upload SARIF to code scanning:
   ```yaml
   - run: pip install cognis-mcpharden
   - run: mcpharden scan . --format sarif --out mcpharden.sarif --fail-on high
   - uses: github/codeql-action/upload-sarif@v3
     with: { sarif_file: mcpharden.sarif }
   ```
   To expose it to agents instead, run `mcpharden mcp` (stdio JSON-RPC MCP server).

## Why

Security and intelligence teams need MCP server hardening linter — capability declarations, transport, tool descriptions without standing up heavyweight infrastructure. `mcpharden` is single-purpose, scriptable, CI-friendly, and self-hostable: point it at a target, get prioritized findings in the format your workflow already speaks (table, JSON, SARIF, HTML), and wire it into agents over MCP when you want it autonomous.

## MCP vulnerability coverage

`mcpharden` maps the documented **2025–2026 MCP attack surface** — every class
below ships as a static detection rule plus a catalog entry (`mcpharden vulndb`)
tied to the real CVEs / advisories:

| Class | What it catches | CVE / source |
|-------|-----------------|--------------|
| **Tool poisoning** | hidden instructions in tool metadata | CVE-2025-54136 (MCPoison), CVE-2025-54135 |
| **Command injection** | tool args → shell/exec (RCE) | CVE-2025-53967, -54073, -53818, -69256, -59834, -53107 |
| **Line jumping** | ANSI/control chars hiding text from review | MCP-38 taxonomy |
| **Tool shadowing** | one server's metadata hijacking another's tools | Invariant Labs |
| **Rug pull** | mutable/dynamic tool re-registration | CVE-2025-54136 |
| **Token passthrough** | upstream token forwarded to tools (confused deputy) | MCP auth spec |
| **OAuth/session binding** | session-id-in-URL, OAuth without PKCE/state | OWASP MCP Cheat Sheet |
| **SSE DNS rebinding** | wildcard CORS on network transport | MCP Toolbox advisory (2026) |
| **Auto-approval** | tool calls run with no human review | Invariant Labs |
| **Supply chain** | unpinned `npx`/`uvx` launch | ox.security advisory |
| **Sampling abuse** | sampling exposed with no rate limit (DoS/credit drain) | Kluster Verify advisory |

```bash
mcpharden vulndb                        # the full catalog (classes + CVEs + detect rules)
mcpharden vulndb --cve CVE-2025-54136   # which classes a CVE maps to
mcpharden vulndb --id MCP-CI-01 --format json
mcpharden rules                         # every detection rule
```

New classes are tracked against the public MCP threat literature (Invariant Labs,
OWASP MCP Tool Poisoning + MCP Security Cheat Sheet, the MCP-38 taxonomy, and the
Vulnerable MCP Project) and the GitHub Advisory Database.

## Install

```bash
pip install cognis-mcpharden
# or, from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
mcpharden --version
mcpharden scan demos/                      # audit server manifests (file or directory)
mcpharden scan demos/ --format sarif --out r.sarif --fail-on high
mcpharden scan demos/ --format html --out report.html
mcpharden posture demos/                   # cross-server fleet correlation + grade
mcpharden mcp                              # expose as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

### Audit your real MCP client config

The riskiest surface is the `mcpServers` block in your **client** config. Point
`configscan` at it (or let it auto-detect Claude Desktop / Cursor / Cline / VS Code):

```bash
mcpharden configscan                       # auto-detect common client configs
mcpharden configscan ~/.cursor/mcp.json    # or a specific file
mcpharden configscan path/to/config.json --format sarif --out mcp.sarif
```

It flags **unpinned `npx`/`uvx` launchers** (supply-chain), **secrets hard-coded
in `env`**, **`sh -c` command lines** (RCE), **cleartext / no-auth remote
servers**, and **blanket auto-approve** lists.

### Catch rug-pulls (tool drift after you trusted a server)

```bash
mcpharden baseline server.json -o server.baseline.json   # pin once, when trusted
mcpharden diff server.json --baseline server.baseline.json --fail-on high
```

`diff` flags any tool whose name/description/`inputSchema` was **added, removed,
or mutated** since the baseline — the tool-poisoning / rug-pull signature
(MCP-RP-01, CVE-2025-54136).

### Fleet posture — cross-server risks a per-server audit can't see

Nobody runs one MCP server. An agent host connects to a *fleet* that shares one
model context and one trust boundary, which creates risks whose evidence is
**split across manifests** and is therefore invisible to a per-server scan.
`posture` correlates the whole directory:

```bash
mcpharden posture ./mcp-servers                 # fleet grade + cross-server findings
mcpharden posture ./mcp-servers --format html --out posture.html
mcpharden posture ./mcp-servers --fail-on high  # CI gate on cross-server risk
mcpharden posture ./mcp-servers --min-grade B   # or gate on the fleet's letter grade
```

It detects **reused credentials across servers** (`fleet.shared_secret`, blast
radius = the whole fleet), **tool-name collisions** (`fleet.tool_collision`, the
precondition for cross-server tool shadowing), an **RCE-server-next-to-exposed-peer
lateral-movement surface** (`fleet.lateral_movement`), **trust-tier / TLS
inconsistency** between network peers, and **failure concentration** — then rolls
the fleet up to a single hardening grade and the one highest-leverage fix. Full
walkthrough, threat model, and diagram: **[docs/POSTURE.md](docs/POSTURE.md)**.

## Built-in demo scenarios

Each scenario folder includes a `SCENARIO.md` describing the situation and the findings to expect.

- [`demos/01-basic/`](demos/01-basic/SCENARIO.md)
- [`demos/01-public-mcp-no-auth/`](demos/01-public-mcp-no-auth/SCENARIO.md)
- [`demos/02-internal-stdio/`](demos/02-internal-stdio/SCENARIO.md)
- [`demos/03-shared-multi-server/`](demos/03-shared-multi-server/SCENARIO.md)

## Output formats

- **Table** (default) — human-readable terminal summary
- **JSON** — machine-readable findings for pipelines
- **SARIF** — drops into GitHub code-scanning / IDE problem panes
- **HTML** — shareable report with severity rollups

## Credits / Built on

Cognis composes and credits the best of open source. This tool builds on / interoperates with:

- [`ModelContextProtocol-Security/mcpserver-audit`](https://github.com/modelcontextprotocol) — fork base
- [`slowmist/MCP-Security-Checklist`](https://github.com/slowmist/MCP-Security-Checklist) — checklist source

Missing a credit? Open a PR — see [CONTRIBUTING.md](CONTRIBUTING.md).

## How it fits the Cognis Neural Suite

`mcpharden` is one of **52 tools** in the [Cognis Neural Suite](https://github.com/cognis-digital). Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents can call them as scoped capabilities.

**Sibling tools in `ai-security`:** [`aegis`](https://github.com/cognis-digital/aegis), [`promptmirror`](https://github.com/cognis-digital/promptmirror), [`ledgermind`](https://github.com/cognis-digital/ledgermind), [`adversa`](https://github.com/cognis-digital/adversa), [`guardpost`](https://github.com/cognis-digital/guardpost), [`hallumark`](https://github.com/cognis-digital/hallumark), [`aicard`](https://github.com/cognis-digital/aicard), [`biascope`](https://github.com/cognis-digital/biascope), [`agentlog`](https://github.com/cognis-digital/agentlog), [`ragshield`](https://github.com/cognis-digital/ragshield)

## Architecture & roadmap

- Design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Planned work: [`ROADMAP.md`](ROADMAP.md)

## Contributing

PRs, new detections, and demo scenarios are welcome under the collaboration-pull model. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Interoperability

`mcpharden` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `mcpharden`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## Responsible use

This is dual-use security software. Use it only against systems, data, and identities you own or are explicitly authorized in writing to test, and in compliance with applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
