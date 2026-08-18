"""Discovery — turn a brand into candidate impersonation domains.

Two kinds of source:

* **Generative** (:func:`generate`) — algorithmic typosquat/combosquat candidates.
  Cheap guesses; most won't be registered. Resolve them before trusting one.
* **Observational** (:func:`discover_certsh`, :func:`discover_urlscan`,
  :func:`discover_openphish`) — hosts that were *actually observed* in CT logs,
  urlscan, or a phishing feed. These come back as real
  :class:`~lookalike_radar.findings.Finding` objects.

Plus :func:`ingest_reported_url`, an intake path so an out-of-band report (an
analyst, an email gateway, a proxy log) lands in the ledger the same way a
discovered host does.

:func:`run_discovery` fans the observational sources out over a brand and returns
the combined findings; hand them to a :class:`~lookalike_radar.ledger.Ledger` to
dedup and persist.
"""

from __future__ import annotations

import logging
from typing import Callable, Iterable, List, Optional
from urllib.parse import urlparse

from ..findings import Finding, Source
from .certsh import discover as discover_certsh
from .feeds import discover_openphish, discover_urlscan
from .permutations import generate

logger = logging.getLogger(__name__)

__all__ = [
    "generate",
    "discover_certsh",
    "discover_urlscan",
    "discover_openphish",
    "ingest_reported_url",
    "run_discovery",
]


def ingest_reported_url(url: str, brand: Optional[str] = None,
                        source: str = Source.REPORTED) -> Finding:
    """Turn a reported phishing URL into a :class:`Finding`.

    Extracts the hostname so an analyst/gateway/proxy report enters the ledger
    on the same footing as a discovered host. Raises ``ValueError`` if no
    hostname can be parsed.
    """
    host = (urlparse(url if "://" in url else "http://" + url).hostname or "").strip().lower()
    if not host:
        raise ValueError(f"could not parse a hostname from {url!r}")
    return Finding(domain=host, brand=brand, source=source)


def run_discovery(
    brand: str,
    *,
    exclude_domains: Optional[Iterable[str]] = None,
    urlscan_api_key: Optional[str] = None,
    use_certsh: bool = True,
    use_urlscan: bool = True,
    use_openphish: bool = True,
    fetcher=None,
) -> List[Finding]:
    """Run the observational sources over ``brand`` and return combined findings.

    Each source is best-effort and independent: one failing narrows coverage but
    never aborts the run. De-dup across sources is left to the ledger's upsert —
    the same host from crt.sh and urlscan is one finding, not two.
    """
    findings: List[Finding] = []
    steps: List[Callable[[], List[Finding]]] = []
    if use_certsh:
        steps.append(lambda: discover_certsh(
            brand, exclude_domains=exclude_domains, fetcher=fetcher))
    if use_urlscan:
        steps.append(lambda: discover_urlscan(
            brand, api_key=urlscan_api_key, exclude_domains=exclude_domains, fetcher=fetcher))
    if use_openphish:
        steps.append(lambda: discover_openphish(
            brand, exclude_domains=exclude_domains, fetcher=fetcher))

    for step in steps:
        try:
            findings.extend(step())
        except Exception as exc:  # noqa: BLE001 - defensive; sources already guard
            logger.warning("discovery source failed: %s", exc)
    return findings
