"""Algorithmic candidate generation — the classic typosquat/combosquat fuzzers.

Given a brand domain, generate the domains an attacker is *likely to register*:
character-level typos (omission, transposition, keyboard slips, homoglyphs),
plus combosquats (brand + a phishing keyword) and TLD swaps. This is pure and
dependency-free — no DNS, no network. It answers "what would you register to
impersonate this brand?"; a later step resolves which of those actually exist.

The candidates are *guesses*, not confirmed domains. Feed them through DNS /
registration checks (see the scoring layer) before treating one as a finding —
generating them is cheap, but most won't be registered.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Set, Tuple

# QWERTY horizontal neighbours — a fat-finger slip lands on an adjacent key.
_KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh",
    "u": "yij", "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdx",
    "d": "sefc", "f": "drgv", "g": "fthb", "h": "gyjn", "j": "hukm", "k": "jil",
    "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
    "0": "9o", "1": "2q", "2": "13", "3": "24", "4": "35", "5": "46",
    "6": "57", "7": "68", "8": "79", "9": "80",
}

# Visually confusable substitutions — how a homoglyph attack fools the eye.
_HOMOGLYPHS = {
    "a": ["4", "@"], "b": ["8"], "e": ["3"], "g": ["9", "q"], "i": ["1", "l", "!"],
    "l": ["1", "i"], "o": ["0"], "s": ["5", "$"], "t": ["7"], "z": ["2"],
    "c": ["("], "0": ["o"], "1": ["l", "i"], "5": ["s"],
}

_VOWELS = "aeiou"

# Commonly abused TLDs beyond the original — cheap, permissive, or made to look
# legitimate (developer TLDs increasingly used for brand impersonation).
DEFAULT_ABUSED_TLDS = [
    "tk", "buzz", "xyz", "top", "ga", "ml", "cf", "gq", "icu", "wang", "live",
    "online", "host", "us", "info", "net", "org", "co", "io", "app", "dev",
    "ai", "tech",
]

# Industry gTLDs an impersonator uses to look on-brand.
DEFAULT_INDUSTRY_TLDS = [
    "insurance", "insure", "health", "finance", "financial", "money", "bank",
    "security", "secure", "trust", "app", "cloud", "digital", "tech",
    "company", "group", "global", "services", "solutions", "support",
]

# Phishing keywords for combosquats (brand+word). Auth/service/action terms an
# attacker bolts onto a brand to make a plausible-looking login/portal host.
DEFAULT_KEYWORDS = [
    "login", "signin", "secure", "verify", "auth", "account", "portal", "access",
    "support", "help", "service", "update", "pay", "payment", "billing",
    "home", "online", "web", "my", "go", "get", "mail", "email", "vpn", "cloud",
    "api", "admin", "corp", "global", "us", "app",
]

# TLDs used when expanding combosquats across namespaces.
_COMBO_TLDS = ["com", "net", "org", "dev", "io", "app", "co", "ai"]


def split_domain(domain: str) -> Tuple[str, str]:
    """Split a domain into (label, tld) on the last dot.

    Naive by design (no public-suffix list), so ``a.co.uk`` splits to
    ``("a.co", "uk")``. Pass the registrable label directly if that matters for
    your brand.
    """
    domain = domain.strip().lower().rstrip(".")
    if "." not in domain:
        return domain, ""
    label, tld = domain.rsplit(".", 1)
    return label, tld


# ---- character-level fuzzers (operate on the label) -----------------------

def _omission(label: str) -> Set[str]:
    return {label[:i] + label[i + 1:] for i in range(len(label))} - {label}


def _repetition(label: str) -> Set[str]:
    return {label[:i] + label[i] + label[i:] for i in range(len(label))}


def _transposition(label: str) -> Set[str]:
    out = set()
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            out.add(label[:i] + label[i + 1] + label[i] + label[i + 2:])
    return out


def _replacement(label: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        for repl in _KEYBOARD.get(ch, ""):
            out.add(label[:i] + repl + label[i + 1:])
    return out


def _insertion(label: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        for ins in _KEYBOARD.get(ch, ""):
            out.add(label[:i] + ins + label[i:])
            out.add(label[:i + 1] + ins + label[i + 1:])
    return out


def _homoglyph(label: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        for repl in _HOMOGLYPHS.get(ch, []):
            out.add(label[:i] + repl + label[i + 1:])
    return out


def _vowel_swap(label: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        if ch in _VOWELS:
            for v in _VOWELS:
                if v != ch:
                    out.add(label[:i] + v + label[i + 1:])
    return out


def _hyphenation(label: str) -> Set[str]:
    # split the brand at each interior position and join with a hyphen
    return {label[:i] + "-" + label[i:] for i in range(1, len(label))}


def _typo_labels(label: str, include_homoglyphs: bool, include_hyphenation: bool) -> Set[str]:
    labels: Set[str] = set()
    labels |= _omission(label)
    labels |= _repetition(label)
    labels |= _transposition(label)
    labels |= _replacement(label)
    labels |= _insertion(label)
    labels |= _vowel_swap(label)
    if include_homoglyphs:
        labels |= _homoglyph(label)
    if include_hyphenation:
        labels |= _hyphenation(label)
    labels.discard(label)
    return {l for l in labels if l}


# ---- public API -----------------------------------------------------------

def generate(
    domain: str,
    *,
    include_typos: bool = True,
    include_homoglyphs: bool = True,
    include_hyphenation: bool = True,
    include_tld_swap: bool = False,
    include_industry_tld: bool = False,
    include_combosquats: bool = False,
    keywords: Optional[Iterable[str]] = None,
    abused_tlds: Optional[Iterable[str]] = None,
    industry_tlds: Optional[Iterable[str]] = None,
) -> List[str]:
    """Generate candidate impersonation domains for ``domain``.

    Typos and homoglyphs keep the original TLD; TLD-swap, industry-TLD, and
    combosquat expansions vary it. The original domain is never returned, and
    the result is sorted and de-duplicated.

    The optional expansions default to *off* — they multiply the candidate count
    and are best reserved for high-value brands where the extra coverage is worth
    the DNS-resolution cost downstream.
    """
    label, tld = split_domain(domain)
    if not label:
        return []
    tld = tld or "com"

    candidates: Set[str] = set()

    if include_typos:
        for l in _typo_labels(label, include_homoglyphs, include_hyphenation):
            candidates.add(f"{l}.{tld}")

    if include_tld_swap:
        for t in (abused_tlds or DEFAULT_ABUSED_TLDS):
            if t.lower() != tld:
                candidates.add(f"{label}.{t.lower()}")

    if include_industry_tld:
        for t in (industry_tlds or DEFAULT_INDUSTRY_TLDS):
            if t.lower() != tld:
                candidates.add(f"{label}.{t.lower()}")

    if include_combosquats:
        words = list(keywords or DEFAULT_KEYWORDS)
        for word in words:
            if word in label:
                continue  # already part of the brand — no new signal
            for t in _COMBO_TLDS:
                if t == tld:
                    combos = [f"{label}{word}", f"{word}{label}",
                              f"{label}-{word}", f"{word}-{label}"]
                else:
                    combos = [f"{label}-{word}", f"{word}-{label}"]
                for c in combos:
                    candidates.add(f"{c}.{t}")

    candidates.discard(domain.strip().lower().rstrip("."))
    return sorted(candidates)
