"""Pluggable enrichment providers.

The engine is vendor-neutral: it does not ship API keys or hardwire any threat-
intel vendor. Instead, enrichment is a Protocol — you bring your own provider
(VirusTotal, Recorded Future, Shodan, an internal feed, whatever) by implementing
:meth:`EnrichmentProvider.enrich`, and the scorer folds the returned signals into
a finding's weaponization evidence.

A provider returns a plain ``dict`` of signals. Keys are up to you; the scorer
treats them as opaque evidence and passes them to the verdict step. Return an
empty dict (never raise) when you have nothing — a provider hiccup should narrow
coverage for one domain, not fail the run.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Protocol, runtime_checkable


@runtime_checkable
class EnrichmentProvider(Protocol):
    """Enriches a single domain with vendor-specific threat signals."""

    #: short, stable tag identifying this provider in the signal blob
    name: str

    def enrich(self, domain: str) -> Dict[str, Any]:
        """Return a dict of signals for ``domain`` (empty dict if none)."""
        ...


class CallableProvider:
    """Wrap a plain ``domain -> dict`` function as an :class:`EnrichmentProvider`.

    Saves writing a class for a one-off lookup::

        vt = CallableProvider("virustotal", lambda d: my_vt_lookup(d))
        score_finding(f, providers=[vt])
    """

    def __init__(self, name: str, fn: Callable[[str], Dict[str, Any]]):
        self.name = name
        self._fn = fn

    def enrich(self, domain: str) -> Dict[str, Any]:
        return self._fn(domain) or {}


def run_providers(domain: str, providers: List[EnrichmentProvider]) -> Dict[str, Any]:
    """Run every provider over a domain, namespaced by provider name.

    Best-effort: a provider that raises is skipped, not fatal. Returns
    ``{provider_name: {...signals}}``.
    """
    out: Dict[str, Any] = {}
    for p in providers:
        try:
            signals = p.enrich(domain) or {}
        except Exception:  # noqa: BLE001 - a provider hiccup must not fail the scan
            signals = {}
        if signals:
            out[getattr(p, "name", p.__class__.__name__)] = signals
    return out
