"""Turn collected signals into a weaponization verdict.

Two scorers, same interface:

* :class:`RulesScorer` — a deterministic ladder over the hard signals. No LLM,
  no network, no API key. This is the default, so the package produces useful
  P1–P4 verdicts out of the box.
* :class:`LLMScorer` — hands the signals to *your* model (any provider) and
  parses a structured verdict back. Bring your own callable; the engine ships no
  model client and no key.

Tier calibration (shared by both): a working credential-harvest / login clone is
**P1**; stood-up impersonation that is mail-capable *or* a brand clone but not
yet confirmed harvesting is **P2**; a registered/parked/placeholder lookalike is
**P3**; benign / dormant / unrelated is **P4**. A mail-capable brand combosquat
can phish by email today regardless of its web page, so an MX record floors the
tier at P2 even behind a parked landing page.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Dict, Optional, Protocol, runtime_checkable

from ..findings import RiskTier

logger = logging.getLogger(__name__)


@runtime_checkable
class Scorer(Protocol):
    """Produces a verdict dict from a signals dict."""

    def score(self, signals: Dict[str, Any]) -> Dict[str, Any]:
        ...


def _verdict(tier: RiskTier, active: bool, confidence: str, rationale: str,
             action: str, **extra: Any) -> Dict[str, Any]:
    v = {
        "risk_tier": tier.value,
        "is_active_phishing": active,
        "confidence": confidence,
        "rationale": rationale,
        "recommended_action": action,
    }
    v.update(extra)
    return v


class RulesScorer:
    """Deterministic weaponization ladder over the hard signals."""

    def score(self, signals: Dict[str, Any]) -> Dict[str, Any]:
        page = signals.get("page") or {}
        dns = signals.get("dns") or {}
        brand_on_page = bool(signals.get("brand_in_page"))
        reachable = bool(page.get("reachable"))
        has_pw = bool(page.get("has_password_input"))
        has_form = bool(page.get("has_form"))
        mail_capable = bool(dns.get("has_mx"))
        resolves = bool(dns.get("has_a")) or reachable
        parked = signals.get("parked")

        # P1 — live credential harvest: a reachable login/password form that
        # also carries the brand. Highest confidence when password + brand align.
        if reachable and has_pw and brand_on_page:
            return _verdict(
                RiskTier.P1, True, "high",
                "Reachable page presents a password/login form and shows the "
                "targeted brand — a working credential-harvest clone.",
                "Raise takedown + block at proxy/EDR now.")

        # P1/P2 — password form without confirmed brand: still a live login trap.
        if reachable and has_pw:
            return _verdict(
                RiskTier.P2, False, "medium",
                "Reachable page presents a password/login form; brand match not "
                "confirmed on-page. Likely credential capture — verify the target.",
                "Investigate + prepare takedown.")

        # P2 — mail-capable impersonation: can phish by email today regardless of
        # what the web page shows. MX floors the tier here.
        if mail_capable:
            page_note = "parked/placeholder web page" if parked else (
                "live web page" if reachable else "no live web page")
            return _verdict(
                RiskTier.P2, False, "medium",
                f"Domain is mail-capable (MX present) with a {page_note}; a brand "
                "combosquat with live mail can run BEC/credential phishing by email "
                "regardless of the site.",
                "Monitor for sending + prepare takedown; consider mail controls.")

        # P2 — brand clone infrastructure standing up (branded page + a form).
        if reachable and brand_on_page and has_form:
            return _verdict(
                RiskTier.P2, False, "medium",
                "Reachable page impersonates the brand and carries an input form "
                "but no password field yet — stood-up impersonation infrastructure.",
                "Monitor closely + prepare takedown.")

        # P3 — a registered/parked/branded placeholder, not weaponized, no mail.
        if resolves or reachable or parked:
            why = "parked/for-sale placeholder" if parked else (
                "resolves but no live phishing signals" if resolves else "reachable placeholder")
            return _verdict(
                RiskTier.P3, False, "medium",
                f"Suspicious lookalike ({why}); not weaponized and not mail-capable.",
                "Monitor — re-score if it goes live or gains MX.")

        # P4 — dormant: doesn't resolve, no page, no mail.
        return _verdict(
            RiskTier.P4, False, "low",
            "No resolving A record, no live page, no MX — dormant registration. "
            "Re-scored automatically if it goes live.",
            "No action; watch for activation.", heuristic=True)


# The system prompt handed to a bring-your-own LLM. Vendor-neutral.
SYSTEM_PROMPT = (
    "You are a senior SOC analyst triaging suspected brand-impersonation domains. "
    "You are given hard signals collected from a suspect domain (live page state, "
    "presence of a login/password form, brand keywords on the page, redirect "
    "behavior, parked-page detection, and mail capability via MX/SPF/DMARC). Judge "
    "how WEAPONIZED the domain is right now, not merely whether it looks similar. "
    "Calibration: a working credential-harvest/login clone is P1; stood-up "
    "impersonation infrastructure that is mail-capable or a brand clone but not yet "
    "confirmed harvesting is P2; a registered/parked/placeholder lookalike is P3; "
    "clearly benign, defensive, or unrelated is P4. Do not over-escalate parked or "
    "for-sale domains UNLESS the domain is mail-capable: a brand combosquat with "
    "live mail (an MX record, especially with SPF or DMARC) can phish by email "
    "TODAY regardless of what its web page shows, so a parked or 'coming soon' page "
    "does NOT lower the tier — treat a mail-capable brand-impersonation domain as "
    "at least P2. Be decisive and concrete; your rationale may be attached to a "
    "takedown request. Respond ONLY with a JSON object with keys: risk_tier "
    "(P1|P2|P3|P4), is_active_phishing (bool), has_login_form (bool), brand_clone "
    "(bool), targets_credentials (bool), confidence (high|medium|low), rationale "
    "(2-3 terse sentences), recommended_action (one terse SOC next step)."
)


def facts_prompt(signals: Dict[str, Any]) -> str:
    """Render collected signals into the facts block for an LLM scorer."""
    p = signals.get("page") or {}
    d = signals.get("dns") or {}
    lines = [
        f"Domain: {signals.get('domain')}",
        f"Targeted brand: {signals.get('brand') or 'unknown'}",
        f"Page reachable: {p.get('reachable')} (HTTP {p.get('status_code')})",
        f"Final URL after redirects: {p.get('final_url')}",
        f"Redirected off the domain: {p.get('redirected_offsite')}",
        f"Has a form: {p.get('has_form')}; has a password field: {p.get('has_password_input')}",
        f"Page title: {p.get('title')!r}",
        f"Brand name appears in page text: {signals.get('brand_in_page')}",
        f"Parked/for-sale page detected: {signals.get('parked')}",
        f"Resolves (A record): {d.get('has_a')} {d.get('a_records')}",
        f"Mail-capable (MX): {d.get('has_mx')} {d.get('mx_hosts')}; "
        f"SPF: {d.get('has_spf')}; DMARC: {d.get('has_dmarc')}",
    ]
    if signals.get("page_text_excerpt"):
        lines.append(f"\nVisible page text (truncated):\n{signals['page_text_excerpt']}")
    return "\n".join(lines)


def _extract_json(text: str) -> Dict[str, Any]:
    """Pull the first JSON object out of an LLM response (tolerant of fences)."""
    if isinstance(text, dict):
        return text
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        raise ValueError("no JSON object in LLM response")
    return json.loads(m.group(0))


class LLMScorer:
    """Score with a bring-your-own model.

    ``llm`` is any callable ``(system_prompt, user_prompt) -> str | dict``. Return
    a JSON string (or an already-parsed dict) matching the schema described in
    :data:`SYSTEM_PROMPT`. Falls back to :class:`RulesScorer` if the model errors
    or returns unparseable output — a scoring run should degrade, not crash.
    """

    def __init__(self, llm: Callable[[str, str], Any],
                 system_prompt: str = SYSTEM_PROMPT,
                 fallback: Optional[Scorer] = None):
        self.llm = llm
        self.system_prompt = system_prompt
        self.fallback = fallback if fallback is not None else RulesScorer()

    def score(self, signals: Dict[str, Any]) -> Dict[str, Any]:
        try:
            raw = self.llm(self.system_prompt, facts_prompt(signals))
            verdict = _extract_json(raw)
            tier = str(verdict.get("risk_tier", "")).upper()
            if tier not in ("P1", "P2", "P3", "P4"):
                raise ValueError(f"invalid risk_tier {tier!r}")
            verdict["risk_tier"] = tier
            verdict["is_active_phishing"] = bool(verdict.get("is_active_phishing"))
            return verdict
        except Exception as e:  # noqa: BLE001 - degrade to rules, keep the signals useful
            logger.warning("LLM scorer failed (%s); falling back to rules", e)
            fb = self.fallback.score(signals)
            fb["llm_error"] = f"{type(e).__name__}: {e}"
            return fb
