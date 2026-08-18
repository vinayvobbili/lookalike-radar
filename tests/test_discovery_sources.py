import pytest

from lookalike_radar import ingest_reported_url, run_discovery
from lookalike_radar.findings import Source
from lookalike_radar.discovery import certsh, feeds


class StubFetcher:
    """Injectable fetcher: canned json/text, or an exception to simulate failure."""

    def __init__(self, json=None, text=None, raise_exc=None):
        self._json = json
        self._text = text
        self._raise = raise_exc
        self.calls = []

    def get_json(self, url, *, params=None, headers=None):
        self.calls.append((url, params, headers))
        if self._raise:
            raise self._raise
        return self._json

    def get_text(self, url, *, params=None, headers=None):
        self.calls.append((url, params, headers))
        if self._raise:
            raise self._raise
        return self._text


# ---- crt.sh ---------------------------------------------------------------

def test_certsh_parses_wildcards_multiline_and_filters_brand():
    rows = [
        {"name_value": "*.example-login.com\nexample-login.com", "issuer_name": "Let's Encrypt"},
        {"name_value": "unrelated.com", "issuer_name": "X"},
        {"name_value": "mail@example-login.com", "issuer_name": "X"},  # email SAN skipped
    ]
    out = certsh.discover("example", fetcher=StubFetcher(json=rows))
    domains = {f.domain for f in out}
    assert domains == {"example-login.com"}  # wildcard stripped, dedup, email skipped
    f = out[0]
    assert f.source == Source.CERT_TRANSPARENCY
    assert f.brand == "example"
    assert f.infrastructure.cert_issuer == "Let's Encrypt"


def test_certsh_excludes_owned_apex_and_its_subdomains():
    rows = [{"name_value": "www.example.com\nexample-login.net", "issuer_name": "X"}]
    out = certsh.discover("example", exclude_domains=["example.com"],
                          fetcher=StubFetcher(json=rows))
    assert {f.domain for f in out} == {"example-login.net"}


def test_certsh_failure_is_empty_not_raised():
    out = certsh.discover("example", fetcher=StubFetcher(raise_exc=RuntimeError("crt.sh down")))
    assert out == []


# ---- urlscan --------------------------------------------------------------

def test_urlscan_parses_page_domain_and_query_shape():
    data = {"results": [
        {"page": {"domain": "example-login.attacker.tk"}},
        {"page": {"domain": "nothing-here.com"}},
        {"page": {}},
    ]}
    stub = StubFetcher(json=data)
    out = feeds.discover_urlscan("example", api_key="KEY", fetcher=stub)
    assert {f.domain for f in out} == {"example-login.attacker.tk"}
    assert out[0].source == Source.URLSCAN
    # api key -> true substring query + header
    _, params, headers = stub.calls[0]
    assert params["q"] == "page.domain:*example*"
    assert headers == {"API-Key": "KEY"}


def test_urlscan_anonymous_is_prefix_query():
    stub = StubFetcher(json={"results": []})
    feeds.discover_urlscan("example", fetcher=stub)
    _, params, headers = stub.calls[0]
    assert params["q"] == "page.domain:example*"
    assert headers is None


# ---- openphish ------------------------------------------------------------

def test_openphish_extracts_hostnames_containing_brand():
    feed = "\n".join([
        "https://example-login.attacker.tk/verify",
        "http://safe.com/",
        "https://sub.exampleportal.io/login?x=1",
    ])
    out = feeds.discover_openphish("example", fetcher=StubFetcher(text=feed))
    assert {f.domain for f in out} == {"example-login.attacker.tk", "sub.exampleportal.io"}
    assert all(f.source == Source.OPENPHISH for f in out)


# ---- intake ---------------------------------------------------------------

def test_ingest_reported_url():
    f = ingest_reported_url("https://Example-Login.tk/verify?a=b", brand="example")
    assert f.domain == "example-login.tk"
    assert f.source == Source.REPORTED
    assert f.brand == "example"


def test_ingest_bare_host():
    assert ingest_reported_url("evil.example.tk").domain == "evil.example.tk"


def test_ingest_hostless_raises():
    with pytest.raises(ValueError):
        ingest_reported_url("")
    with pytest.raises(ValueError):
        ingest_reported_url("http:///only/a/path")


# ---- run_discovery orchestration -----------------------------------------

def test_run_discovery_combines_and_survives_a_bad_source():
    # certsh returns one host; urlscan fetcher raises; openphish returns one host.
    certsh_stub = StubFetcher(json=[{"name_value": "example-a.com", "issuer_name": "X"}])
    op_stub = StubFetcher(text="https://example-b.io/x")

    # give each source its own fetcher by calling them directly through run_discovery's
    # fetcher param won't differ per source, so instead assert the best-effort combine
    # using a fetcher that serves json (certsh + urlscan) and text (openphish).
    class Multi(StubFetcher):
        def get_json(self, url, *, params=None, headers=None):
            if "crt.sh" in url:
                return [{"name_value": "example-a.com", "issuer_name": "X"}]
            raise RuntimeError("urlscan down")  # simulate one failing source

        def get_text(self, url, *, params=None, headers=None):
            return "https://example-b.io/x"

    out = run_discovery("example", fetcher=Multi())
    assert {f.domain for f in out} == {"example-a.com", "example-b.io"}
