import json

from lookalike_radar import Finding, Ledger, RiskTier, Source, Weaponization
from lookalike_radar.cli import main


def test_permute_stdout(capsys):
    rc = main(["permute", "example.com"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "exaple.com" in out  # an omission candidate


def test_permute_json(capsys):
    rc = main(["permute", "example.com", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert "example.com" not in data  # original excluded
    assert all(c.endswith(".com") for c in data)


def test_permute_combosquats(capsys):
    main(["permute", "example.com", "--combosquats", "--keywords", "login"])
    out = capsys.readouterr().out
    assert "example-login.com" in out


def test_list_json(tmp_path, capsys):
    db = tmp_path / "f.db"
    lg = Ledger(db)
    lg.upsert(Finding(domain="examp1e.com", brand="example", source=Source.PERMUTATION,
                      weaponization=Weaponization(tier=RiskTier.P2)))
    rc = main(["--db", str(db), "list", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data[0]["domain"] == "examp1e.com"
    assert data[0]["weaponization"]["tier"] == "P2"


def test_list_filter_by_status(tmp_path, capsys):
    db = tmp_path / "f.db"
    lg = Ledger(db)
    lg.upsert(Finding(domain="a.com"))
    lg.upsert(Finding(domain="b.com"))
    lg.set_status("a.com", "takedown")
    main(["--db", str(db), "list", "--status", "takedown", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert [f["domain"] for f in data] == ["a.com"]


def test_version(capsys):
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0
    assert "lookalike-radar" in capsys.readouterr().out
