"""SQLite storage for scans (AGENT_PLAN Phase 4 requirement / Project 07 rubric).

Every run writes its discovered subdomains, resolved DNS records (IPs, CNAME
chains, NS), and flagged findings into a local database — ``subtake.db`` next
to the phase JSON files — so results stay queryable, e.g.:

    sqlite3 data/output/subtake.db \\
        "SELECT subdomain, severity FROM findings WHERE confidence='HIGH'"

Pure stdlib (sqlite3) — no extra dependency, works identically on Windows and
Linux, and bundles automatically in the PyInstaller build.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from src.models import Phase1Result, Phase2Result, Phase3Result

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    started_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subdomains (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    name    TEXT NOT NULL,
    source  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dns_records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id),
    name         TEXT NOT NULL,
    resolved     INTEGER NOT NULL,
    dns_status   TEXT NOT NULL,
    ip_addresses TEXT NOT NULL DEFAULT '',
    ipv6         TEXT NOT NULL DEFAULT '',
    cname_chain  TEXT NOT NULL DEFAULT '',
    ns           TEXT NOT NULL DEFAULT '',
    http_status  INTEGER,
    http_title   TEXT,
    http_error   TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id),
    subdomain    TEXT NOT NULL,
    type         TEXT NOT NULL,
    service      TEXT,
    cname_target TEXT,
    evidence     TEXT,
    confidence   TEXT NOT NULL,
    severity     TEXT NOT NULL,
    remediation  TEXT,
    ref_links    TEXT
);
"""


class ScanDatabase:
    """One connection per database file; one ``scans`` row per run."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def new_scan(self, target: str) -> int:
        """Insert the scans header row; returns the scan_id."""
        started_at = datetime.now(timezone.utc).isoformat()
        cursor = self._conn.execute(
            "INSERT INTO scans (target, started_at) VALUES (?, ?)", (target, started_at)
        )
        self._conn.commit()
        return int(cursor.lastrowid)

    def save_phase1(self, scan_id: int, result: Phase1Result) -> int:
        """Store every (subdomain, source) pair; returns the row count."""
        rows = [
            (scan_id, entry.name, source)
            for entry in result.subdomains
            for source in entry.sources
        ]
        self._conn.executemany(
            "INSERT INTO subdomains (scan_id, name, source) VALUES (?, ?, ?)", rows
        )
        self._conn.commit()
        return len(rows)

    def save_phase2(self, scan_id: int, result: Phase2Result) -> int:
        """Store resolved records: IPs, CNAME chains, NS, HTTP facts."""
        rows = []
        for record in result.records:
            rows.append(
                (
                    scan_id,
                    record.name,
                    int(record.resolved),
                    record.dns_status,
                    ",".join(record.a),
                    ",".join(record.aaaa),
                    " -> ".join(record.cname_chain),
                    ",".join(record.ns),
                    record.http.status,
                    record.http.title,
                    record.http.error,
                )
            )
        self._conn.executemany(
            """INSERT INTO dns_records
               (scan_id, name, resolved, dns_status, ip_addresses, ipv6,
                cname_chain, ns, http_status, http_title, http_error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        self._conn.commit()
        return len(rows)

    def save_phase3(self, scan_id: int, result: Phase3Result) -> int:
        """Store flagged findings with evidence/severity/remediation."""
        rows = [
            (
                scan_id,
                finding.subdomain,
                finding.type,
                finding.service,
                finding.cname_target,
                finding.evidence,
                finding.confidence,
                finding.severity,
                finding.remediation,
                " | ".join(finding.references),
            )
            for finding in result.findings
        ]
        self._conn.executemany(
            """INSERT INTO findings
               (scan_id, subdomain, type, service, cname_target, evidence,
                confidence, severity, remediation, ref_links)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        self._conn.commit()
        return len(rows)

    # ------------------------------------------------------------------
    # Deletion (subtake clean / GUI "Clear saved results")
    # ------------------------------------------------------------------

    def _domain_scan_ids(self, target: str) -> list[int]:
        cursor = self._conn.execute(
            "SELECT id FROM scans WHERE target = ?", (target,)
        )
        return [int(row[0]) for row in cursor.fetchall()]

    def count_domain_records(self, target: str) -> dict[str, int]:
        """How many stored rows belong to this domain (for delete previews)."""
        scan_ids = self._domain_scan_ids(target)
        counts: dict[str, int] = {
            "scans": len(scan_ids),
            "subdomains": 0,
            "dns_records": 0,
            "findings": 0,
        }
        if not scan_ids:
            return counts
        placeholders = ",".join("?" * len(scan_ids))
        for table in ("subdomains", "dns_records", "findings"):
            cursor = self._conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE scan_id IN ({placeholders})",  # noqa: S608 — fixed table names
                scan_ids,
            )
            counts[table] = int(cursor.fetchone()[0])
        return counts

    def delete_domain_records(self, target: str) -> dict[str, int]:
        """Delete every stored record for one domain; returns rows removed.

        Rows are matched through ``scans.target`` so other domains stored in
        the same database file are never touched.
        """
        scan_ids = self._domain_scan_ids(target)
        counts: dict[str, int] = {
            "scans": len(scan_ids),
            "subdomains": 0,
            "dns_records": 0,
            "findings": 0,
        }
        if not scan_ids:
            return counts
        placeholders = ",".join("?" * len(scan_ids))
        for table in ("subdomains", "dns_records", "findings"):
            cursor = self._conn.execute(
                f"DELETE FROM {table} WHERE scan_id IN ({placeholders})",  # noqa: S608 — fixed table names
                scan_ids,
            )
            counts[table] = cursor.rowcount
        self._conn.execute("DELETE FROM scans WHERE target = ?", (target,))
        self._conn.commit()
        return counts
