import pytest

from lookalike_radar import Finding, RiskTier, Source, Status, Weaponization
from lookalike_radar.findings import Infrastructure


def test_domain_is_normalized():
    f = Finding(domain="  ExAmp1e.COM.  ")
    assert f.domain == "examp1e.com"


def test_empty_domain_rejected():
    with pytest.raises(ValueError):
        Finding(domain="   ")


def test_string_status_coerced_to_enum():
    f = Finding(domain="x.com", status="monitoring")
    assert f.status is Status.MONITORING


def test_tier_property_reads_through_weaponization():
    f = Finding(domain="x.com")
    assert f.tier is None
    f.weaponization = Weaponization(tier=RiskTier.P1, is_active_phishing=True)
    assert f.tier is RiskTier.P1


def test_finding_dict_round_trip():
    f = Finding(
        domain="examp1e.com", brand="example", source=Source.CERT_TRANSPARENCY,
        weaponization=Weaponization(
            tier=RiskTier.P2, is_active_phishing=False,
            signals={"mx": True}, verdict={"rationale": "mail-capable"},
            scored_at="2026-08-18T00:00:00+00:00",
        ),
        infrastructure=Infrastructure(registrar="NameCheap", ip_addresses=["1.2.3.4"]),
        notes="watch",
    )
    back = Finding.from_dict(f.to_dict())
    assert back.domain == f.domain
    assert back.brand == "example"
    assert back.tier is RiskTier.P2
    assert back.weaponization.signals == {"mx": True}
    assert back.infrastructure.registrar == "NameCheap"
    assert back.infrastructure.ip_addresses == ["1.2.3.4"]
    assert back.notes == "watch"


def test_weaponization_from_dict_none():
    assert Weaponization.from_dict(None) is None
    assert Weaponization.from_dict({}) is None
