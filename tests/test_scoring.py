from lookalike_radar import (
    Finding,
    LLMScorer,
    RulesScorer,
    RiskTier,
    Source,
    evidence_summary,
    score_domain,
    score_finding,
)
from lookalike_radar.scoring import collect_signals
from lookalike_radar.scoring.signals import _looks_parked


# ---- fake network seams ---------------------------------------------------

def page(reachable=True, status=200, form=False, pw=False, title=None,
         content_length=2000, final_url=None, offsite=False):
    return {
        "reachable": reachable, "status_code": status, "final_url": final_url,
        "redirected_offsite": offsite, "has_form": form, "has_password_input": pw,
        "title": title, "content_length": content_length, "error": None,
    }


def dns(a=None, mx=None, spf=False, dmarc=False):
    a = a or []
    mx = mx or []
    return {"has_a": bool(a), "a_records": a, "has_mx": bool(mx), "mx_hosts": mx,
            "has_spf": spf, "has_dmarc": dmarc, "error": None}


def fetcher(sig, text=""):
    return lambda domain: (sig, text)


def resolver(sig):
    return lambda domain: sig


# ---- RulesScorer ladder ---------------------------------------------------

def _score(page_sig=None, dns_sig=None, brand="example", text=""):
    sig = collect_signals("examp1e.com", brand=brand,
                          page_fetcher=fetcher(page_sig or page(reachable=False), text),
                          dns_resolver=resolver(dns_sig or dns()))
    return RulesScorer().score(sig), sig


def test_p1_live_credential_harvest():
    v, _ = _score(page_sig=page(pw=True, form=True), text="Sign in to your example account")
    assert v["risk_tier"] == "P1"
    assert v["is_active_phishing"] is True


def test_p2_password_form_without_brand():
    v, _ = _score(page_sig=page(pw=True, form=True), text="please log in here")
    assert v["risk_tier"] == "P2"
    assert v["is_active_phishing"] is False


def test_p2_mail_capable_even_if_parked():
    v, _ = _score(page_sig=page(content_length=200), dns_sig=dns(mx=["mx.attacker.tk"]),
                  text="this domain is for sale")
    assert v["risk_tier"] == "P2"
    assert "mail-capable" in v["rationale"].lower()


def test_p2_brand_clone_infra():
    v, _ = _score(page_sig=page(form=True), text="Welcome to example — your account portal")
    assert v["risk_tier"] == "P2"


def test_p3_registered_placeholder_no_mail():
    v, _ = _score(page_sig=page(content_length=100), dns_sig=dns(a=["1.2.3.4"]), text="hello")
    assert v["risk_tier"] == "P3"


def test_p3_parked_no_mail():
    v, _ = _score(page_sig=page(content_length=300), text="buy this domain")
    assert v["risk_tier"] == "P3"


def test_p4_dormant():
    v, _ = _score(page_sig=page(reachable=False), dns_sig=dns())
    assert v["risk_tier"] == "P4"
    assert v.get("heuristic") is True


# ---- signals --------------------------------------------------------------

def test_brand_in_page_detection():
    sig = collect_signals("examp1e.com", brand="Example",
                          page_fetcher=fetcher(page(), "Log in to ExampleBank now"),
                          dns_resolver=resolver(dns()))
    assert sig["brand_in_page"] is True


def test_looks_parked_none_when_unreachable():
    assert _looks_parked(page(reachable=False), "") is None


def test_looks_parked_true_on_marker():
    assert _looks_parked(page(), "This domain is for sale via Sedo") is True


def test_collect_signals_survives_fetcher_exception():
    def boom(domain):
        raise RuntimeError("network down")
    sig = collect_signals("x.com", page_fetcher=boom, dns_resolver=resolver(dns()))
    assert sig["page"]["reachable"] is False


# ---- score_domain / score_finding ----------------------------------------

def test_score_domain_returns_weaponization():
    w = score_domain("examp1e.com",
                     page_fetcher=fetcher(page(pw=True), "log in"),
                     dns_resolver=resolver(dns(a=["9.9.9.9"])))
    assert w.tier is RiskTier.P2
    assert w.scored_at is not None
    assert w.signals["dns"]["a_records"] == ["9.9.9.9"]


def test_score_finding_fills_verdict_and_ips():
    f = Finding(domain="examp1e.com", brand="example", source=Source.PERMUTATION)
    score_finding(f, page_fetcher=fetcher(page(pw=True), "sign in to example"),
                  dns_resolver=resolver(dns(a=["5.5.5.5"])))
    assert f.tier is RiskTier.P1
    assert f.infrastructure.ip_addresses == ["5.5.5.5"]


# ---- LLMScorer ------------------------------------------------------------

def test_llm_scorer_parses_json():
    def fake_llm(system, user):
        return '```json\n{"risk_tier": "p1", "is_active_phishing": true, ' \
               '"confidence": "high", "rationale": "clone"}\n```'
    v = LLMScorer(fake_llm).score({"domain": "x.com", "page": {}, "dns": {}})
    assert v["risk_tier"] == "P1"  # upper-cased
    assert v["is_active_phishing"] is True


def test_llm_scorer_falls_back_on_error():
    def broken_llm(system, user):
        raise RuntimeError("model offline")
    sig = collect_signals("x.com", page_fetcher=fetcher(page(reachable=False)),
                          dns_resolver=resolver(dns()))
    v = LLMScorer(broken_llm).score(sig)
    assert v["risk_tier"] == "P4"  # rules fallback
    assert "model offline" in v["llm_error"]


def test_llm_scorer_falls_back_on_bad_tier():
    def bad_llm(system, user):
        return '{"risk_tier": "CRITICAL"}'
    sig = collect_signals("x.com", page_fetcher=fetcher(page(reachable=False)),
                          dns_resolver=resolver(dns()))
    v = LLMScorer(bad_llm).score(sig)
    assert v["risk_tier"] in ("P1", "P2", "P3", "P4")
    assert "llm_error" in v


# ---- evidence summary -----------------------------------------------------

def test_evidence_summary():
    w = score_domain("examp1e.com", brand="example",
                     page_fetcher=fetcher(page(pw=True, title="Example Login"),
                                          "sign in to example"),
                     dns_resolver=resolver(dns(a=["1.1.1.1"], mx=["mx.tk"])))
    text = evidence_summary(w)
    assert "Assessment: P1" in text
    assert "password/login form present" in text
    assert "mail-capable" in text


def test_evidence_summary_safe_on_none():
    assert evidence_summary(None) == ""
