from lookalike_radar import CallableProvider, run_providers, score_domain
from lookalike_radar.scoring.scorer import facts_prompt


def fetcher_unreachable(domain):
    return {"reachable": False, "error": "x"}, ""


def dns_empty(domain):
    return {"has_a": False, "a_records": [], "has_mx": False, "mx_hosts": [],
            "has_spf": False, "has_dmarc": False, "error": None}


def test_callable_provider():
    p = CallableProvider("vt", lambda d: {"malicious": 3})
    assert p.name == "vt"
    assert p.enrich("x.com") == {"malicious": 3}


def test_callable_provider_none_becomes_empty():
    assert CallableProvider("x", lambda d: None).enrich("d") == {}


def test_run_providers_namespaces_and_skips_failures():
    good = CallableProvider("good", lambda d: {"score": 1})
    empty = CallableProvider("empty", lambda d: {})

    class Boom:
        name = "boom"
        def enrich(self, d):
            raise RuntimeError("down")

    out = run_providers("x.com", [good, empty, Boom()])
    assert out == {"good": {"score": 1}}  # empty dropped, boom skipped


def test_providers_folded_into_signals_and_prompt():
    prov = CallableProvider("virustotal", lambda d: {"malicious": 5, "reputation": -20})
    w = score_domain("examp1e.com", brand="example", providers=[prov],
                     page_fetcher=fetcher_unreachable, dns_resolver=dns_empty)
    assert w.signals["providers"] == {"virustotal": {"malicious": 5, "reputation": -20}}
    prompt = facts_prompt(w.signals)
    assert "virustotal" in prompt
    assert "malicious" in prompt


def test_no_providers_leaves_signals_clean():
    w = score_domain("examp1e.com", page_fetcher=fetcher_unreachable, dns_resolver=dns_empty)
    assert "providers" not in w.signals
