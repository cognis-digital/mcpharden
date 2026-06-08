# MCPHARDEN — MCP server hardening linter — capability declarations, transport, tool descriptions

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `ai-security`

[![PyPI](https://img.shields.io/pypi/v/cognis-mcpharden.svg)](https://pypi.org/project/cognis-mcpharden/)
[![CI](https://github.com/cognis-digital/mcpharden/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/mcpharden/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

MCP server hardening linter — capability declarations, transport, tool descriptions.

## Install

```bash
pip install cognis-mcpharden
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
mcpharden --version
mcpharden scan demos/                          # run against bundled demo
mcpharden scan demos/ --format sarif --out r.sarif --fail-on high
mcpharden mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-public-mcp-no-auth/` — see [`SCENARIO.md`](demos/01-public-mcp-no-auth/SCENARIO.md)
- `demos/02-internal-stdio/` — see [`SCENARIO.md`](demos/02-internal-stdio/SCENARIO.md)
- `demos/03-shared-multi-server/` — see [`SCENARIO.md`](demos/03-shared-multi-server/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
