"""Scoring — is this lookalike a live phishing kit, or just a parked typo?

Collect hard signals (:func:`~lookalike_radar.scoring.signals.collect_signals`)
and run them through a :class:`~lookalike_radar.scoring.scorer.Scorer` to get a
P1–P4 weaponization verdict. The default is the zero-dependency
:class:`RulesScorer`; pass an :class:`LLMScorer` to use your own model.

::

    from lookalike_radar import Ledger
    from lookalike_radar.scoring import score_finding

    ledger = Ledger("findings.db")
    for f in ledger.all():
        ledger.upsert(score_finding(f))   # fills in the weaponization verdict
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

from ..findings import Finding, Infrastructure, RiskTier, Weaponization, _utcnow_iso
from .scorer import LLMScorer, RulesScorer, Scorer, SYSTEM_PROMPT, facts_prompt
from .signals import collect_signals

__all__ = [
    "score_domain",
    "score_finding",
    "evidence_summary",
    "collect_signals",
    "Scorer",
    "RulesScorer",
    "LLMScorer",
    "SYSTEM_PROMPT",
    "facts_prompt",
]


def score_domain(
    domain: str,
    brand: Optional[str] = None,
    *,
    scorer: Optional[Scorer] = None,
    page_fetcher: Optional[Callable[[str], Tuple[Dict[str, Any], str]]] = None,
    dns_resolver: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Weaponization:
    """Collect signals for ``domain`` and return a :class:`Weaponization` verdict.

    Uses :class:`RulesScorer` unless you pass a ``scorer`` (e.g. an
    :class:`LLMScorer`). The ``page_fetcher`` / ``dns_resolver`` seams are for
    testing or custom transports.
    """
    scorer = scorer or RulesScorer()
    signals = collect_signals(domain, brand=brand,
                              page_fetcher=page_fetcher, dns_resolver=dns_resolver)
    verdict = scorer.score(signals)
    tier = verdict.get("risk_tier")
    return Weaponization(
        tier=RiskTier(tier) if tier in ("P1", "P2", "P3", "P4") else None,
        is_active_phishing=bool(verdict.get("is_active_phishing")),
        signals=signals,
        verdict=verdict,
        scored_at=_utcnow_iso(),
    )


def score_finding(finding: Finding, *, scorer: Optional[Scorer] = None,
                  page_fetcher=None, dns_resolver=None) -> Finding:
    """Score a finding in place: fill its weaponization verdict and, if empty,
    its resolved A records. Returns the same finding for chaining into an upsert."""
    w = score_domain(finding.domain, brand=finding.brand, scorer=scorer,
                     page_fetcher=page_fetcher, dns_resolver=dns_resolver)
    finding.weaponization = w
    a_records = (w.signals.get("dns") or {}).get("a_records") or []
    if a_records and not finding.infrastructure.ip_addresses:
        finding.infrastructure.ip_addresses = list(a_records)
    return finding


def evidence_summary(weaponization: Optional[Weaponization]) -> str:
    """Render a verdict into a plain-text evidence block for a takedown request /
    notification. Safe on ``None`` and partial verdicts."""
    if not weaponization:
        return ""
    v = weaponization.verdict or {}
    s = weaponization.signals or {}
    p, d = s.get("page") or {}, s.get("dns") or {}
    lines = []
    if v:
        active = "ACTIVE PHISHING" if v.get("is_active_phishing") else "not confirmed active"
        lines.append(f"Assessment: {v.get('risk_tier')} — {active} "
                     f"(confidence {v.get('confidence')})")
        if v.get("rationale"):
            lines.append(f"Rationale: {v['rationale']}")
    facts = []
    if p.get("reachable"):
        facts.append(f"live page (HTTP {p.get('status_code')})")
    if p.get("has_password_input"):
        facts.append("password/login form present")
    elif p.get("has_form"):
        facts.append("input form present")
    if s.get("brand_in_page"):
        facts.append("brand name on page")
    if p.get("title"):
        facts.append(f"title {p['title']!r}")
    if d.get("has_mx"):
        facts.append("mail-capable (MX present)")
    if s.get("parked"):
        facts.append("parked-page markers")
    if facts:
        lines.append("Signals: " + "; ".join(facts))
    return "\n".join(lines)
