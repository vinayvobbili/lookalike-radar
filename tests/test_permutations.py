from lookalike_radar import generate_permutations as gen
from lookalike_radar.discovery import permutations as P


def test_split_domain_naive():
    assert P.split_domain("Example.COM") == ("example", "com")
    assert P.split_domain("a.co.uk") == ("a.co", "uk")
    assert P.split_domain("nodot") == ("nodot", "")


def test_typos_keep_tld_and_exclude_original():
    out = gen("example.com")
    assert "example.com" not in out
    assert all(c.endswith(".com") for c in out)
    # omission of a char is present
    assert "exaple.com" in out
    # transposition
    assert "exapmle.com" in out


def test_homoglyph_toggle():
    with_h = set(gen("google.com", include_homoglyphs=True))
    without_h = set(gen("google.com", include_homoglyphs=False))
    # single-substitution homoglyph: one 'o' -> '0' (o->0 is homoglyph-only,
    # not a keyboard neighbour), so it appears only with homoglyphs enabled.
    assert "go0gle.com" in with_h
    assert "go0gle.com" not in without_h


def test_hyphenation():
    out = gen("acmebank.com", include_hyphenation=True)
    assert "acme-bank.com" in out


def test_tld_swap_and_industry():
    swap = gen("example.com", include_typos=False, include_tld_swap=True,
               abused_tlds=["xyz", "io"])
    assert set(swap) == {"example.xyz", "example.io"}
    ind = gen("example.com", include_typos=False, include_industry_tld=True,
              industry_tlds=["insurance"])
    assert ind == ["example.insurance"]


def test_combosquats():
    out = gen("example.com", include_typos=False, include_combosquats=True,
              keywords=["login"])
    assert "examplelogin.com" in out
    assert "example-login.com" in out
    assert "loginexample.com" in out
    assert "login-example.com" in out
    # other TLDs get only the hyphenated variants
    assert "example-login.io" in out
    assert "examplelogin.io" not in out


def test_combosquat_skips_word_already_in_brand():
    out = gen("acmebank.com", include_typos=False, include_combosquats=True,
              keywords=["bank"])
    assert not any("bank" in c and "acmebank" not in c for c in out)


def test_output_sorted_and_deduped():
    out = gen("example.com")
    assert out == sorted(out)
    assert len(out) == len(set(out))


def test_invalid_domain():
    assert gen("") == []
    assert gen("   ") == []
