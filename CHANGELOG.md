# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-18

Initial release: a vendor-neutral engine for discovering and scoring
brand-impersonation (lookalike / typosquat / combosquat) domains.

### Added

- **Data core** — `Finding` model with `Status` / `RiskTier` enums (stdlib-only),
  a SQLite `Ledger` that dedups by domain and preserves analyst triage across
  re-discovery, and pluggable `EnrichmentProvider` / `Sink` Protocols with
  console / JSONL / multi reference sinks.
- **Discovery** — algorithmic permutations (typo, homoglyph, hyphenation,
  TLD-swap, industry-TLD, combosquat); a crt.sh certificate-transparency sweep;
  urlscan.io and OpenPhish FQDN-substring sources; a reported-URL intake path;
  and a best-effort `run_discovery` orchestrator.
- **Scoring** — hard-signal collection (page fetch, login/password form,
  brand-on-page, MX/SPF/DMARC mail capability, parked-page heuristic, DNS
  resolution) with a deterministic zero-dependency `RulesScorer` and an
  `LLMScorer` that accepts any bring-your-own model callable and degrades to
  rules on error. `evidence_summary` renders a takedown-ready block.
- **Enrichment** — `CallableProvider` and provider results folded into the
  scoring signal blob and the LLM facts prompt.
- **CLI** — `lookalike-radar` with `permute`, `scan`, `score`, and `list`
  subcommands and `--json` output.
- Typed (`py.typed`), MIT-licensed.
