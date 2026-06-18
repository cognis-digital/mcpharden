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

<!-- cognis:domains:start -->
## Domains

**Primary domain:** AI & ML  ·  **JTF MERIDIAN division:** ATHENA-PRIME · SAGE

**Topics:** `cognis` `ai` `llm` `machine-learning` `mcp` `agent-security`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

## Install

```bash
pip install "git+https://github.com/cognis-digital/mcpharden.git"
# or, from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
mcpharden --version
mcpharden scan demos/                      # run against the bundled demo
mcpharden scan demos/ --format sarif --out r.sarif --fail-on high
mcpharden scan demos/ --format html --out report.html
mcpharden mcp                              # expose as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

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
