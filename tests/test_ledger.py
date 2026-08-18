import io

from lookalike_radar import (
    ConsoleSink,
    Finding,
    JsonlSink,
    Ledger,
    MultiSink,
    RiskTier,
    Source,
    Status,
    Weaponization,
)


def _ledger(tmp_path):
    return Ledger(tmp_path / "f.db")


def test_upsert_and_get(tmp_path):
    lg = _ledger(tmp_path)
    lg.upsert(Finding(domain="examp1e.com", brand="example", source=Source.PERMUTATION))
    got = lg.get("EXAMP1E.COM")  # case-insensitive
    assert got is not None
    assert got.brand == "example"
    assert got.status is Status.NEW


def test_rediscovery_dedups_to_one_row(tmp_path):
    lg = _ledger(tmp_path)
    lg.upsert(Finding(domain="examp1e.com", source=Source.PERMUTATION))
    lg.upsert(Finding(domain="examp1e.com", source=Source.CERT_TRANSPARENCY))
    assert lg.count() == 1
    assert lg.get("examp1e.com").source == Source.CERT_TRANSPARENCY


def test_triage_status_survives_rediscovery(tmp_path):
    lg = _ledger(tmp_path)
    lg.upsert(Finding(domain="examp1e.com"))
    lg.set_status("examp1e.com", Status.MONITORING, notes="analyst looked")
    # a fresh discovery must NOT reset status back to NEW or wipe notes
    lg.upsert(Finding(domain="examp1e.com", source=Source.URLSCAN))
    got = lg.get("examp1e.com")
    assert got.status is Status.MONITORING
    assert got.notes == "analyst looked"


def test_first_seen_anchored_last_seen_advances(tmp_path):
    lg = _ledger(tmp_path)
    lg.upsert(Finding(domain="x.com", first_seen="2026-01-01T00:00:00+00:00",
                      last_seen="2026-01-01T00:00:00+00:00"))
    lg.upsert(Finding(domain="x.com", first_seen="2026-06-01T00:00:00+00:00",
                      last_seen="2026-06-01T00:00:00+00:00"))
    got = lg.get("x.com")
    assert got.first_seen == "2026-01-01T00:00:00+00:00"
    assert got.last_seen == "2026-06-01T00:00:00+00:00"


def test_brand_preserved_when_rediscovery_lacks_it(tmp_path):
    lg = _ledger(tmp_path)
    lg.upsert(Finding(domain="x.com", brand="example"))
    lg.upsert(Finding(domain="x.com"))  # no brand this time
    assert lg.get("x.com").brand == "example"


def test_prior_weaponization_kept_when_absent(tmp_path):
    lg = _ledger(tmp_path)
    lg.upsert(Finding(domain="x.com",
                      weaponization=Weaponization(tier=RiskTier.P1, is_active_phishing=True)))
    lg.upsert(Finding(domain="x.com"))  # unscored re-sighting
    assert lg.get("x.com").tier is RiskTier.P1


def test_filter_by_status_and_brand(tmp_path):
    lg = _ledger(tmp_path)
    lg.upsert(Finding(domain="a.com", brand="acme"))
    lg.upsert(Finding(domain="b.com", brand="example"))
    lg.set_status("a.com", Status.TAKEDOWN)
    assert [f.domain for f in lg.all(status=Status.TAKEDOWN)] == ["a.com"]
    assert [f.domain for f in lg.all(brand="example")] == ["b.com"]


def test_persistence_across_instances(tmp_path):
    p = tmp_path / "f.db"
    Ledger(p).upsert(Finding(domain="x.com", brand="example"))
    assert Ledger(p).get("x.com").brand == "example"


def test_console_sink_renders_tier_first():
    buf = io.StringIO()
    f = Finding(domain="examp1e.com", brand="example", source=Source.PERMUTATION,
                weaponization=Weaponization(tier=RiskTier.P1))
    ConsoleSink(stream=buf).emit(f)
    line = buf.getvalue().strip()
    assert line.startswith("P1")
    assert "example" in line and "examp1e.com" in line


def test_jsonl_and_multi_sink(tmp_path):
    path = tmp_path / "out.jsonl"
    buf = io.StringIO()
    sink = MultiSink(JsonlSink(str(path)), ConsoleSink(stream=buf))
    sink.emit([Finding(domain="a.com"), Finding(domain="b.com")])
    assert len(path.read_text().strip().splitlines()) == 2
    assert "a.com" in buf.getvalue() and "b.com" in buf.getvalue()


def test_multi_sink_survives_a_broken_sink(tmp_path):
    class Broken:
        def emit(self, findings):
            raise RuntimeError("boom")

    buf = io.StringIO()
    MultiSink(Broken(), ConsoleSink(stream=buf)).emit(Finding(domain="a.com"))
    assert "a.com" in buf.getvalue()  # good sink still ran
