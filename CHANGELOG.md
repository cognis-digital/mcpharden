# Changelog

All notable changes to mcpharden are documented here. This project adheres to
[Semantic Versioning](https://semver.org/). The public API
(`mcpharden.__all__`) is stable across this release.

## [0.5.0]

### Fixed — real bugs
- **Rug-pull blind spot with duplicate tool names.** `build_baseline` keyed a
  dict by tool name, so a server advertising two tools under the *same* name
  (e.g. two `search` tools) collapsed to a single baseline entry — a rug pull
  that mutated only one of the duplicates was invisible to `mcpharden diff`.
  Baselines now pin the full multiset of hashes per name and `diff_baseline`
  compares multisets, so a poisoned duplicate can no longer hide behind its
  honest twin. Old single-hash baseline files remain readable (back-compatible).
  Regression demo: `demos/17_duplicate_tool_rugpull.py`.
- **Wildcard origin missed in a mixed list.** `transport.wildcard_origin` only
  fired when `allowed_origins` was exactly `"*"` or `["*"]`, so a manifest that
  listed real origins *and* a `"*"` (`["https://trusted", "*"]`) — still
  effectively "any origin" — was not flagged. The check now detects a wildcard
  anywhere in the list while leaving explicit-only lists clean (no new false
  positives). Demo: `demos/19_wildcard_origin_bugfix.py`.

### Added — hardening & clearer errors
- `load_manifest` now raises a clear `ManifestError` for a directory path, an
  empty/whitespace-only file, and reports the actual JSON root type when the
  root is not an object.
- `configaudit.audit_config` returns a `config.malformed` finding (instead of
  raising `AttributeError`) when the config root is not a JSON object;
  `audit_config_path` raises a clear `ValueError` for empty / invalid-JSON /
  directory inputs.
- `diff_baseline` raises a clear `ValueError` when handed a non-object baseline.
- `mcpharden rules` now also lists the client-config (`config.*`) and rug-pull
  baseline (`rugpull.*`) rules (52 rules total).

### Added — tests & demos
- Test suite expanded roughly 4× (edge cases + error paths across core,
  baseline, configaudit, vuln-class detectors, CLI, MCP server, SARIF/HTML
  output, robustness/fuzz, and detector boundaries). `python -m pytest -q` green.
- Demo scenarios expanded from 5 to 20 (see [docs/DEMOS.md](docs/DEMOS.md)); each
  runs offline and exits 0.
