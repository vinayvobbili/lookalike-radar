"""A small SQLite ledger that dedups findings and remembers analyst triage.

Discovery runs surface domains; analysts then triage them (relevant vs not,
which brand, raise a takedown). That triage state — not the raw discovery — is
what a monthly brand-protection report is built from, so it needs a durable home
that survives re-discovery. This is that home.

One row per domain. Re-discovering a domain UPSERTs: ``last_seen`` and freshly
resolved infrastructure/weaponization advance, but analyst-owned fields
(``status``, ``brand`` once set, ``notes``) are preserved. WAL mode lets a scan
write while a dashboard reads without "database is locked".
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from .findings import Finding, Infrastructure, Status, Weaponization, _utcnow_iso

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    domain              TEXT PRIMARY KEY,
    source              TEXT,
    brand               TEXT,
    status              TEXT NOT NULL DEFAULT 'new',
    first_seen          TEXT,
    last_seen           TEXT,
    notes               TEXT,
    -- weaponization verdict
    weaponization_tier  TEXT,
    weaponization_active INTEGER,
    weaponization_json  TEXT,
    weaponization_scored_at TEXT,
    -- infrastructure pivots (lists stored as JSON arrays)
    registrar           TEXT,
    registrant_org      TEXT,
    ip_addresses        TEXT,
    nameservers         TEXT,
    cert_issuer         TEXT,
    registered_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_brand ON findings(brand);
"""


class Ledger:
    """A durable, deduped store of :class:`~lookalike_radar.findings.Finding`.

    Thread-safe for the common case (a scan writing while a reader reads):
    each operation opens its own short-lived connection, and writes are
    serialized by a process-local lock on top of SQLite's own locking.
    """

    def __init__(self, path: Union[str, Path] = "lookalike_findings.db"):
        self.path = Path(path)
        self._write_lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ---- writes -----------------------------------------------------------

    def upsert(self, finding: Finding) -> Finding:
        """Insert a finding, or merge it into the existing row for its domain.

        Preserves analyst-owned state on an existing row: ``status`` is never
        downgraded back to ``new`` by re-discovery, an assigned ``brand`` and
        analyst ``notes`` are kept, and ``first_seen`` is anchored to the
        earliest sighting. Everything freshly observed (last_seen, source,
        infrastructure, weaponization) advances.
        """
        with self._write_lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM findings WHERE domain = ?", (finding.domain,)
            ).fetchone()
            merged = self._merge(existing, finding)
            conn.execute(
                """
                INSERT INTO findings (
                    domain, source, brand, status, first_seen, last_seen, notes,
                    weaponization_tier, weaponization_active, weaponization_json,
                    weaponization_scored_at, registrar, registrant_org,
                    ip_addresses, nameservers, cert_issuer, registered_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(domain) DO UPDATE SET
                    source=excluded.source, brand=excluded.brand,
                    status=excluded.status, first_seen=excluded.first_seen,
                    last_seen=excluded.last_seen, notes=excluded.notes,
                    weaponization_tier=excluded.weaponization_tier,
                    weaponization_active=excluded.weaponization_active,
                    weaponization_json=excluded.weaponization_json,
                    weaponization_scored_at=excluded.weaponization_scored_at,
                    registrar=excluded.registrar,
                    registrant_org=excluded.registrant_org,
                    ip_addresses=excluded.ip_addresses,
                    nameservers=excluded.nameservers,
                    cert_issuer=excluded.cert_issuer,
                    registered_at=excluded.registered_at
                """,
                self._to_row(merged),
            )
        return merged

    def upsert_many(self, findings: Iterable[Finding]) -> int:
        """Upsert a batch; returns the count written."""
        n = 0
        for f in findings:
            self.upsert(f)
            n += 1
        return n

    def set_status(self, domain: str, status: Union[Status, str],
                   notes: Optional[str] = None) -> bool:
        """Analyst triage: set a domain's disposition (and optionally notes)."""
        status = Status(status) if isinstance(status, str) else status
        domain = domain.strip().lower().rstrip(".")
        with self._write_lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE findings SET status=?, notes=COALESCE(?, notes) "
                "WHERE domain=?",
                (status.value, notes, domain),
            )
            return cur.rowcount > 0

    # ---- reads ------------------------------------------------------------

    def get(self, domain: str) -> Optional[Finding]:
        domain = domain.strip().lower().rstrip(".")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE domain=?", (domain,)
            ).fetchone()
        return self._from_row(row) if row else None

    def all(self, status: Optional[Union[Status, str]] = None,
            brand: Optional[str] = None) -> List[Finding]:
        clauses, params = [], []
        if status is not None:
            clauses.append("status=?")
            params.append(Status(status).value if isinstance(status, str) else status.value)
        if brand is not None:
            clauses.append("brand=?")
            params.append(brand)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings{where} ORDER BY last_seen DESC", params
            ).fetchall()
        return [self._from_row(r) for r in rows]

    def count(self, status: Optional[Union[Status, str]] = None) -> int:
        return len(self.all(status=status))

    # ---- helpers ----------------------------------------------------------

    @staticmethod
    def _merge(existing: Optional[sqlite3.Row], incoming: Finding) -> Finding:
        if existing is None:
            return incoming
        prior = Ledger._from_row(existing)
        # analyst-owned fields win over re-discovery
        if prior.status != Status.NEW:
            incoming.status = prior.status
        incoming.brand = incoming.brand or prior.brand
        incoming.notes = prior.notes if incoming.notes is None else incoming.notes
        incoming.first_seen = min(prior.first_seen, incoming.first_seen)
        incoming.last_seen = max(prior.last_seen, incoming.last_seen)
        # keep the prior verdict/infra if this sighting didn't bring a fresh one
        incoming.weaponization = incoming.weaponization or prior.weaponization
        if incoming.infrastructure == Infrastructure():
            incoming.infrastructure = prior.infrastructure
        return incoming

    @staticmethod
    def _to_row(f: Finding) -> tuple:
        w = f.weaponization
        infra = f.infrastructure
        return (
            f.domain, f.source, f.brand, f.status.value, f.first_seen,
            f.last_seen, f.notes,
            w.tier.value if (w and w.tier) else None,
            int(w.is_active_phishing) if w else None,
            json.dumps(w.to_dict()) if w else None,
            w.scored_at if w else None,
            infra.registrar, infra.registrant_org,
            json.dumps(infra.ip_addresses), json.dumps(infra.nameservers),
            infra.cert_issuer, infra.registered_at,
        )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Finding:
        weaponization = None
        if row["weaponization_json"]:
            weaponization = Weaponization.from_dict(json.loads(row["weaponization_json"]))
        infra = Infrastructure(
            registrar=row["registrar"],
            registrant_org=row["registrant_org"],
            ip_addresses=json.loads(row["ip_addresses"]) if row["ip_addresses"] else [],
            nameservers=json.loads(row["nameservers"]) if row["nameservers"] else [],
            cert_issuer=row["cert_issuer"],
            registered_at=row["registered_at"],
        )
        return Finding(
            domain=row["domain"],
            source=row["source"],
            brand=row["brand"],
            status=Status(row["status"]),
            first_seen=row["first_seen"] or _utcnow_iso(),
            last_seen=row["last_seen"] or _utcnow_iso(),
            weaponization=weaponization,
            infrastructure=infra,
            notes=row["notes"],
        )
