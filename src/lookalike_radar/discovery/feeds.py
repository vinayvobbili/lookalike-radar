"""FQDN-substring discovery: urlscan.io and OpenPhish.

These close a blind spot that both permutation fuzzing and CT sweeps share: a
malicious *host label* under a legitimate, aged third-party domain, served behind
a wildcard TLS cert — e.g. ``brand-login.somerealestatesite.example``. The brand
appears in no registered lookalike domain and in no certificate SAN, so neither
approach can see it. It IS visible to anything that observes the live page or the
resolved FQDN, which is exactly what these sources do:

  * urlscan.io — searches the brand keyword across the full page hostname,
                 catching subdomain abuse and combosquats. With an API key this
                 is a true substring match; anonymously it's a prefix match.
  * OpenPhish  — the community phishing-URL feed, matched on hostname.

Both yield full FQDNs (not just the registrable apex). Best-effort throughout: a
source hiccup narrows one run's coverage, it never fails the scan.
"""

from __future__ import annotations

import logging
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from ..findings import Finding, Source
from ._http import Fetcher, default_fetcher

logger = logging.getLogger(__name__)

URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"


def _host_of(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").strip().lower().rstrip(".")


def _excluded(host: str, excluded: Iterable[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in excluded)


def discover_urlscan(
    brand: str,
    *,
    api_key: Optional[str] = None,
    exclude_domains: Optional[Iterable[str]] = None,
    size: int = 100,
    fetcher: Optional[Fetcher] = None,
) -> List[Finding]:
    """Search urlscan.io for scanned pages whose hostname contains ``brand``.

    With ``api_key`` the query is a true ``*brand*`` substring match; without it
    urlscan does a ``brand*`` prefix match (still catches labels that start with
    the brand). Best-effort — a failure yields ``[]``.
    """
    brand = (brand or "").strip().lower()
    if not brand:
        return []
    fetcher = fetcher or default_fetcher()
    excluded = {d.strip().lower().rstrip(".") for d in (exclude_domains or [])}
    query = f"page.domain:*{brand}*" if api_key else f"page.domain:{brand}*"
    headers = {"API-Key": api_key} if api_key else None

    try:
        data = fetcher.get_json(URLSCAN_SEARCH, params={"q": query, "size": size},
                                headers=headers)
    except Exception as exc:  # noqa: BLE001
        logger.warning("urlscan query for %r failed: %s", brand, exc)
        return []

    seen, findings = set(), []
    for result in (data or {}).get("results", []):
        host = ((result.get("page") or {}).get("domain") or "").strip().lower().rstrip(".")
        if not host or brand not in host or host in seen or _excluded(host, excluded):
            continue
        seen.add(host)
        findings.append(Finding(domain=host, brand=brand, source=Source.URLSCAN))
    logger.info("urlscan: %d candidate hosts for brand %r", len(findings), brand)
    return findings


def discover_openphish(
    brand: str,
    *,
    exclude_domains: Optional[Iterable[str]] = None,
    fetcher: Optional[Fetcher] = None,
) -> List[Finding]:
    """Scan the OpenPhish community feed for hostnames containing ``brand``."""
    brand = (brand or "").strip().lower()
    if not brand:
        return []
    fetcher = fetcher or default_fetcher()
    excluded = {d.strip().lower().rstrip(".") for d in (exclude_domains or [])}

    try:
        text = fetcher.get_text(OPENPHISH_FEED)
    except Exception as exc:  # noqa: BLE001
        logger.warning("OpenPhish feed fetch failed: %s", exc)
        return []

    seen, findings = set(), []
    for line in text.splitlines():
        host = _host_of(line.strip())
        if not host or brand not in host or host in seen or _excluded(host, excluded):
            continue
        seen.add(host)
        findings.append(Finding(domain=host, brand=brand, source=Source.OPENPHISH))
    logger.info("OpenPhish: %d candidate hosts for brand %r", len(findings), brand)
    return findings
