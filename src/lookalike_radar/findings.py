"""The core data model: a Finding, and the enums that classify it.

A *finding* is one suspicious domain (or full FQDN) that a discovery source
surfaced — a lookalike registration, a combosquat host under a legitimate apex,
a reported phishing URL. Discovery produces findings; scoring enriches them with
a weaponization verdict; a ledger dedups and remembers analyst triage across
runs.

This module is deliberately dependency-free (stdlib only) so the model can be
imported anywhere without pulling in DNS, HTTP, or an LLM client.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Status(str, Enum):
    """Analyst triage disposition for a finding.

    A finding is ``NEW`` until a human classifies it. The rest are terminal-ish
    states the ledger preserves across re-discovery so a domain isn't re-triaged
    every run.
    """

    NEW = "new"
    MONITORING = "monitoring"
    TAKEDOWN = "takedown"
    IRRELEVANT = "irrelevant"
    OWNED = "owned"  # a domain we (the brand) legitimately own — benign


class RiskTier(str, Enum):
    """How *weaponized* a suspicious domain is right now — the scoring verdict.

    This is about live threat, not mere similarity. A mail-capable brand
    combosquat can phish by email today even behind a parked web page, so
    mail capability alone floors it at P2.
    """

    P1 = "P1"  # live, weaponized — working credential-harvest / login clone
    P2 = "P2"  # strong impersonation: mail-capable OR brand clone, not yet confirmed harvesting
    P3 = "P3"  # suspicious lookalike, not weaponized and not mail-capable
    P4 = "P4"  # benign / defensive / unrelated


# Well-known discovery sources. `source` on a Finding is a free string — a
# custom discovery plugin may use any tag — but these are the built-ins.
class Source:
    PERMUTATION = "permutation"      # algorithmic typo/combo permutations
    CERT_TRANSPARENCY = "cert_ct"    # crt.sh certificate-transparency sweep
    URLSCAN = "urlscan"              # urlscan.io hostname search (FQDN substring)
    OPENPHISH = "openphish"          # OpenPhish community feed
    REPORTED = "reported"            # out-of-band report (analyst, gateway, proxy)
    MANUAL = "manual"                # hand-entered


@dataclass
class Weaponization:
    """A scoring verdict: is this lookalike a live phishing kit?

    ``signals`` holds the hard evidence collected (page live, login form, MX/SPF/
    DMARC, parked-page detection); ``verdict`` holds the judged read (from an LLM
    or a rules engine). Both are free-form dicts so callers can carry whatever
    their scorer produces without a schema change here.
    """

    tier: Optional[RiskTier] = None
    is_active_phishing: bool = False
    signals: Dict[str, Any] = field(default_factory=dict)
    verdict: Dict[str, Any] = field(default_factory=dict)
    scored_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["tier"] = self.tier.value if self.tier else None
        return d

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> Optional["Weaponization"]:
        if not d:
            return None
        tier = d.get("tier")
        return cls(
            tier=RiskTier(tier) if tier else None,
            is_active_phishing=bool(d.get("is_active_phishing")),
            signals=d.get("signals") or {},
            verdict=d.get("verdict") or {},
            scored_at=d.get("scored_at"),
        )


@dataclass
class Infrastructure:
    """Infrastructure pivots for a finding — shared actor footprint.

    Persisted so campaign clustering can group domains that share a registrar,
    registrant org, hosting IPs, or nameservers. All best-effort; any field may
    be ``None`` when the pivot couldn't be resolved.
    """

    registrar: Optional[str] = None
    registrant_org: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    cert_issuer: Optional[str] = None
    registered_at: Optional[str] = None  # domain creation date (WHOIS), ISO


@dataclass
class Finding:
    """One suspicious domain/FQDN and everything known about it.

    ``domain`` is the identity — the ledger keys on it, so the same host
    surfaced by two sources is one finding, not two. ``brand`` is the protected
    brand keyword it impersonates. Timestamps track discovery recency;
    ``weaponization`` and ``infrastructure`` are filled in by scoring/enrichment.
    """

    domain: str
    source: str = Source.MANUAL
    brand: Optional[str] = None
    status: Status = Status.NEW
    first_seen: str = field(default_factory=_utcnow_iso)
    last_seen: str = field(default_factory=_utcnow_iso)
    weaponization: Optional[Weaponization] = None
    infrastructure: Infrastructure = field(default_factory=Infrastructure)
    notes: Optional[str] = None

    def __post_init__(self) -> None:
        self.domain = (self.domain or "").strip().lower().rstrip(".")
        if not self.domain:
            raise ValueError("Finding.domain must be a non-empty hostname")
        if isinstance(self.status, str):
            self.status = Status(self.status)

    @property
    def tier(self) -> Optional[RiskTier]:
        return self.weaponization.tier if self.weaponization else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "source": self.source,
            "brand": self.brand,
            "status": self.status.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "weaponization": self.weaponization.to_dict() if self.weaponization else None,
            "infrastructure": asdict(self.infrastructure),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        infra = d.get("infrastructure") or {}
        return cls(
            domain=d["domain"],
            source=d.get("source", Source.MANUAL),
            brand=d.get("brand"),
            status=Status(d.get("status", "new")),
            first_seen=d.get("first_seen") or _utcnow_iso(),
            last_seen=d.get("last_seen") or _utcnow_iso(),
            weaponization=Weaponization.from_dict(d.get("weaponization")),
            infrastructure=Infrastructure(**infra) if infra else Infrastructure(),
            notes=d.get("notes"),
        )
