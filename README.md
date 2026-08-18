# lookalike-radar

Discover and score brand-impersonation domains — lookalikes, typosquats, and
combosquats — then dedup and track analyst triage over time.

Most typosquat tooling stops at *"a similar domain exists."* The interesting
question is **"is this lookalike a live phishing kit, or just a parked typo?"**
`lookalike-radar` is built around that question: it discovers candidate
impersonation domains from several sources, scores how *weaponized* each one is,
and keeps a durable ledger so a domain is triaged once, not every run.

It is **vendor-neutral by design**. The engine ships no API keys and hardwires no
threat-intel vendor or messaging platform. Enrichment providers and notification
sinks are pluggable Protocols — you bring VirusTotal / Recorded Future / Shodan /
your own feed, and Webex / Slack / a webhook / a log line.

## Install

```
pip install lookalike-radar            # core: model + ledger + protocols (stdlib only)
pip install "lookalike-radar[all]"     # + optional DNS / HTTP / WHOIS extras used by discovery & scoring
```

## Quick start

```python
from lookalike_radar import Finding, Ledger, ConsoleSink, Source

ledger = Ledger("findings.db")

# A discovery source hands you candidate domains; record them.
ledger.upsert(Finding(domain="examp1e.com", brand="example", source=Source.PERMUTATION))
ledger.upsert(Finding(domain="example-login.com", brand="example", source=Source.CERT_TRANSPARENCY))

# Re-running is safe: the ledger dedups by domain and preserves analyst triage.
ledger.set_status("examp1e.com", "monitoring", notes="parked, watching")

ConsoleSink().emit(ledger.all())
```

## Discovery

Two kinds of source feed the ledger:

```python
from lookalike_radar import generate_permutations, run_discovery, Ledger

# Generative: algorithmic typo/combosquat candidates (pure, no network).
candidates = generate_permutations("example.com", include_combosquats=True)

# Observational: hosts actually seen in CT logs, urlscan, and OpenPhish.
ledger = Ledger("findings.db")
ledger.upsert_many(run_discovery("example", exclude_domains=["example.com"],
                                 urlscan_api_key="..."))  # key optional
```

Permutations *guess* what an attacker might register (resolve them before
trusting one); the observational sources report FQDNs that already exist —
including combosquats and wildcard-cloaked subdomain abuse under a legitimate
apex that permutations and CT sweeps both miss. Every source is best-effort: one
being slow or down narrows a run's coverage, it never aborts the scan. Networked
sources need the `[http]` extra.

## Concepts

- **Finding** — one suspicious domain and everything known about it: the brand it
  impersonates, its discovery source, a weaponization verdict, and infrastructure
  pivots (registrar, registrant org, IPs, nameservers) for campaign clustering.
- **Risk tier** — the weaponization verdict. `P1` live/weaponized, `P2` strong
  impersonation (a mail-capable combosquat is at least P2 — it can phish by email
  today regardless of its web page), `P3` suspicious but not weaponized, `P4`
  benign.
- **Ledger** — a SQLite store that dedups by domain and remembers triage across
  runs. Re-discovery advances what's freshly observed but never downgrades an
  analyst's disposition.
- **Providers** — pluggable enrichment (`enrich(domain) -> signals`).
- **Sinks** — pluggable delivery (`emit(findings)`); ships console + JSONL.

## Status

Alpha. The data core (findings, ledger, providers, sinks) and discovery sources
(permutations, certificate transparency, urlscan/OpenPhish) are in place.
Weaponization scoring — the "is this a live phishing kit?" verdict — lands next.

## License

MIT
