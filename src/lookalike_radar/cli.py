"""Command-line interface: ``lookalike-radar``.

    lookalike-radar permute example.com --combosquats
    lookalike-radar scan example --apex example.com --score
    lookalike-radar score examp1e.com --brand example
    lookalike-radar list --status new

Discovery/scoring subcommands need the network extras
(``pip install 'lookalike-radar[all]'``); ``permute`` and ``list`` do not.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .findings import Finding, Status
from .ledger import Ledger
from .sinks import ConsoleSink

DEFAULT_DB = "lookalike_findings.db"
DEFAULT_SCORE_LIMIT = 20


def _split(csv: Optional[str]) -> Optional[List[str]]:
    if not csv:
        return None
    return [x.strip() for x in csv.split(",") if x.strip()]


# ---- subcommands ----------------------------------------------------------

def _cmd_permute(a: argparse.Namespace) -> int:
    from .discovery import generate
    cands = generate(
        a.domain,
        include_homoglyphs=not a.no_homoglyphs,
        include_tld_swap=a.tld_swap,
        include_industry_tld=a.industry_tld,
        include_combosquats=a.combosquats,
        keywords=_split(a.keywords),
    )
    if a.json:
        print(json.dumps(cands))
    else:
        for c in cands:
            print(c)
        print(f"\n{len(cands)} candidates for {a.domain}", file=sys.stderr)
    return 0


def _cmd_scan(a: argparse.Namespace) -> int:
    from .discovery import run_discovery
    from .scoring import score_finding

    key = a.urlscan_key or os.environ.get("LOOKALIKE_URLSCAN_KEY")
    findings = run_discovery(
        a.brand,
        exclude_domains=a.apex,
        urlscan_api_key=key,
        use_certsh=not a.no_certsh,
        use_urlscan=not a.no_urlscan,
        use_openphish=not a.no_openphish,
    )
    print(f"discovered {len(findings)} candidate hosts for brand '{a.brand}'",
          file=sys.stderr)

    if a.score and findings:
        limit = a.limit
        to_score = findings[:limit]
        if len(findings) > limit:
            print(f"scoring first {limit} of {len(findings)} (raise with --limit "
                  f"0 for all)", file=sys.stderr)
        for f in to_score:
            try:
                score_finding(f)
            except Exception as e:  # noqa: BLE001
                print(f"  score failed for {f.domain}: {e}", file=sys.stderr)

    ledger = Ledger(a.db)
    ledger.upsert_many(findings)

    stored = ledger.all(brand=a.brand)
    if a.json:
        print(json.dumps([f.to_dict() for f in stored], indent=2))
    else:
        ConsoleSink().emit(sorted(stored, key=lambda x: (x.tier.value if x.tier else "P9")))
    return 0


def _cmd_score(a: argparse.Namespace) -> int:
    from .scoring import evidence_summary, score_domain
    w = score_domain(a.domain, brand=a.brand)
    if a.json:
        print(json.dumps(w.to_dict(), indent=2, default=str))
    else:
        print(f"{a.domain}  ->  {w.tier.value if w.tier else '--'}")
        print(evidence_summary(w))
    if a.db_write:
        Ledger(a.db).upsert(Finding(domain=a.domain, brand=a.brand, weaponization=w))
    return 0


def _cmd_list(a: argparse.Namespace) -> int:
    ledger = Ledger(a.db)
    status = Status(a.status) if a.status else None
    findings = ledger.all(status=status, brand=a.brand)
    if a.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        ConsoleSink().emit(findings)
        print(f"\n{len(findings)} findings", file=sys.stderr)
    return 0


# ---- parser ---------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lookalike-radar",
                                description="Discover and score brand-impersonation domains.")
    p.add_argument("--version", action="version", version=f"lookalike-radar {__version__}")
    p.add_argument("--db", default=DEFAULT_DB, help=f"ledger path (default: {DEFAULT_DB})")
    sub = p.add_subparsers(dest="cmd", required=True)

    pm = sub.add_parser("permute", help="generate typosquat/combosquat candidates (no network)")
    pm.add_argument("domain")
    pm.add_argument("--combosquats", action="store_true", help="brand+keyword combos")
    pm.add_argument("--tld-swap", action="store_true", help="swap onto abused TLDs")
    pm.add_argument("--industry-tld", action="store_true", help="brand on industry gTLDs")
    pm.add_argument("--no-homoglyphs", action="store_true")
    pm.add_argument("--keywords", help="comma-separated combosquat keywords")
    pm.add_argument("--json", action="store_true")
    pm.set_defaults(func=_cmd_permute)

    sc = sub.add_parser("scan", help="discover hosts for a brand (CT/urlscan/OpenPhish)")
    sc.add_argument("brand")
    sc.add_argument("--apex", action="append", default=[],
                    help="owned apex to exclude (repeatable)")
    sc.add_argument("--urlscan-key", help="urlscan API key (or $LOOKALIKE_URLSCAN_KEY)")
    sc.add_argument("--score", action="store_true", help="weaponization-score discovered hosts")
    sc.add_argument("--limit", type=int, default=DEFAULT_SCORE_LIMIT,
                    help=f"max hosts to score (default {DEFAULT_SCORE_LIMIT}; 0 = all)")
    sc.add_argument("--no-certsh", action="store_true")
    sc.add_argument("--no-urlscan", action="store_true")
    sc.add_argument("--no-openphish", action="store_true")
    sc.add_argument("--json", action="store_true")
    sc.set_defaults(func=_cmd_scan)

    so = sub.add_parser("score", help="score a single domain")
    so.add_argument("domain")
    so.add_argument("--brand", help="targeted brand keyword")
    so.add_argument("--db-write", action="store_true", help="also upsert into the ledger")
    so.add_argument("--json", action="store_true")
    so.set_defaults(func=_cmd_score)

    ls = sub.add_parser("list", help="list ledger findings")
    ls.add_argument("--status", choices=[s.value for s in Status])
    ls.add_argument("--brand")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(func=_cmd_list)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "limit", None) == 0:
        args.limit = 10**9  # "all"
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
