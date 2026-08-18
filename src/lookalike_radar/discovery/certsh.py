"""Certificate-transparency discovery via crt.sh.

A new TLS certificate naming a brand is a strong tell of attacker preparation —
you provision the cert before you stand up the phishing page. crt.sh indexes the
public CT logs and is free, so a brand-keyword substring query surfaces freshly
issued certs on impersonation domains.

This complements permutations: permutations *guess* what an attacker might
register; CT reports certs that were *actually issued*, including combosquats and
hosts you'd never have enumerated.
"""

from __future__ import annotations

import logging
from typing import Iterable, List, Optional

from ..findings import Finding, Infrastructure, Source
from ._http import Fetcher, default_fetcher

logger = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/"


def _clean_names(name_value: str) -> Iterable[str]:
    """crt.sh packs one-or-many SANs into ``name_value``, newline-separated,
    sometimes wildcarded. Yield bare hostnames."""
    for raw in (name_value or "").splitlines():
        host = raw.strip().lower().lstrip("*.").rstrip(".")
        if host and "@" not in host:  # skip email SANs
            yield host


def discover(
    brand: str,
    *,
    exclude_domains: Optional[Iterable[str]] = None,
    fetcher: Optional[Fetcher] = None,
) -> List[Finding]:
    """Find domains with a recently issued cert whose name contains ``brand``.

    Best-effort: a crt.sh hiccup (it is frequently slow/overloaded) yields an
    empty list, never an exception — the sweep re-runs next cycle. Cross-run
    dedup is the ledger's job; this only de-dupes within the single response.
    """
    brand = (brand or "").strip().lower()
    if not brand:
        return []
    fetcher = fetcher or default_fetcher()
    excluded = {d.strip().lower().rstrip(".") for d in (exclude_domains or [])}

    try:
        rows = fetcher.get_json(CRT_SH_URL, params={"q": f"%{brand}%", "output": "json"})
    except Exception as exc:  # noqa: BLE001 - best-effort; never fail the sweep
        logger.warning("crt.sh query for %r failed: %s", brand, exc)
        return []

    seen = set()
    findings: List[Finding] = []
    for row in rows or []:
        issuer = row.get("issuer_name") if isinstance(row, dict) else None
        for host in _clean_names(row.get("name_value", "") if isinstance(row, dict) else ""):
            if brand not in host or host in excluded or host in seen:
                continue
            # skip a host that is exactly, or a subdomain of, an excluded apex
            if any(host == d or host.endswith("." + d) for d in excluded):
                continue
            seen.add(host)
            findings.append(Finding(
                domain=host, brand=brand, source=Source.CERT_TRANSPARENCY,
                infrastructure=Infrastructure(cert_issuer=issuer),
            ))
    logger.info("crt.sh: %d candidate hosts for brand %r", len(findings), brand)
    return findings
