"""lookalike-radar — discover and score brand-impersonation domains.

A vendor-neutral engine for lookalike / typosquat / combosquat domain
monitoring: discover candidate impersonation domains from several sources, score
how *weaponized* each one is (is it a live phishing kit, or just a parked typo?),
and dedup + track analyst triage in a durable ledger.

Enrichment providers and notification sinks are pluggable Protocols, so the
engine carries no API keys, no vendor lock-in, and no delivery opinion — you
bring those. See :mod:`lookalike_radar.providers` and
:mod:`lookalike_radar.sinks`.

Quick start::

    from lookalike_radar import Finding, Ledger, ConsoleSink, Source

    ledger = Ledger("findings.db")
    f = ledger.upsert(Finding(domain="examp1e.com", brand="example",
                              source=Source.PERMUTATION))
    ConsoleSink().emit(ledger.all())
"""

from .findings import (
    Finding,
    Infrastructure,
    RiskTier,
    Source,
    Status,
    Weaponization,
)
from .ledger import Ledger
from .providers import EnrichmentProvider, run_providers
from .sinks import ConsoleSink, JsonlSink, MultiSink, Sink
from .discovery import (
    generate as generate_permutations,
    ingest_reported_url,
    run_discovery,
)

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "Weaponization",
    "Infrastructure",
    "Status",
    "RiskTier",
    "Source",
    "Ledger",
    "EnrichmentProvider",
    "run_providers",
    "Sink",
    "ConsoleSink",
    "JsonlSink",
    "MultiSink",
    "generate_permutations",
    "run_discovery",
    "ingest_reported_url",
    "__version__",
]
