"""Tests for the SQLite storage module (Student Guide Phase 4 requirement)."""

import sqlite3

from src.discovery.dns_client import DnsStatus
from src.models import (
    Finding,
    HttpInfo,
    Phase1Result,
    Phase2Result,
    Phase3Result,
    ResolvedRecord,
    SubdomainEntry,
)
from src.storage.sqlite_store import ScanDatabase


def _phase1():
    entry = SubdomainEntry("blog.example.com")
    entry.add_source("crtsh")
    entry.add_source("bruteforce")
    return Phase1Result(
        target="example.com", generated_at="t1", sources_used=["crtsh"],
        subdomains=[entry],
    )


def _phase2():
    record = ResolvedRecord(
        name="blog.example.com", resolved=True, dns_status=DnsStatus.NXDOMAIN,
        a=["1.2.3.4"], aaaa=["::1"],
        cname_chain=["blog.example.com", "dead.example.github.io"],
        http=HttpInfo(status=404, title="Site not found"),
    )
    return Phase2Result(target="example.com", generated_at="t2", records=[record])


def _phase3():
    return Phase3Result(
        target="example.com", generated_at="t3",
        findings=[
            Finding(
                subdomain="blog.example.com", type="CNAME_NXDOMAIN",
                service="unknown", cname_target="dead.example.github.io",
                evidence="target NXDOMAIN", confidence="MEDIUM", severity="HIGH",
                references=["https://ref.example"],
                remediation="Remove the dangling CNAME record.",
            )
        ],
        summary={"total_scanned": 1, "vulnerable": 0,
                 "by_confidence": {"HIGH": 0, "MEDIUM": 1, "LOW": 0}},
    )


def test_full_storage_roundtrip(tmp_path):
    db_path = tmp_path / "subtake.db"
    db = ScanDatabase(db_path)
    scan_id = db.new_scan("example.com")
    assert scan_id >= 1
    assert db.save_phase1(scan_id, _phase1()) == 2  # one subdomain, two sources
    assert db.save_phase2(scan_id, _phase2()) == 1
    assert db.save_phase3(scan_id, _phase3()) == 1
    db.close()

    conn = sqlite3.connect(db_path)
    try:
        # scans header
        rows = conn.execute("SELECT target, started_at FROM scans").fetchall()
        assert rows == [("example.com", "t1")] or rows[0][0] == "example.com"
        # subdomains: every (name, source) pair stored
        pairs = conn.execute(
            "SELECT name, source FROM subdomains ORDER BY source"
        ).fetchall()
        assert pairs == [
            ("blog.example.com", "bruteforce"),
            ("blog.example.com", "crtsh"),
        ]
        # dns records: IPs, CNAME chain, status, HTTP facts
        rec = conn.execute(
            "SELECT name, resolved, dns_status, ip_addresses, ipv6, cname_chain,"
            " http_status, http_title FROM dns_records"
        ).fetchone()
        assert rec[0] == "blog.example.com"
        assert rec[1] == 1
        assert rec[2] == "NXDOMAIN"
        assert rec[3] == "1.2.3.4"
        assert rec[4] == "::1"
        assert rec[5] == "blog.example.com -> dead.example.github.io"
        assert rec[6] == 404
        assert rec[7] == "Site not found"
        # findings: severity + remediation queryable
        finding = conn.execute(
            "SELECT subdomain, type, severity, confidence, remediation, ref_links"
            " FROM findings"
        ).fetchone()
        assert finding[0] == "blog.example.com"
        assert finding[1] == "CNAME_NXDOMAIN"
        assert finding[2] == "HIGH"
        assert finding[3] == "MEDIUM"
        assert finding[4] == "Remove the dangling CNAME record."
        assert "https://ref.example" in finding[5]
    finally:
        conn.close()


def test_multiple_scans_are_kept(tmp_path):
    db_path = tmp_path / "subtake.db"
    db = ScanDatabase(db_path)
    first = db.new_scan("example.com")
    db.save_phase1(first, _phase1())
    second = db.new_scan("test.com")
    db.save_phase1(second, _phase1())
    db.close()
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0] == 4
    finally:
        conn.close()


def test_db_creates_parent_directories(tmp_path):
    db = ScanDatabase(tmp_path / "deep" / "nested" / "subtake.db")
    scan_id = db.new_scan("example.com")
    assert scan_id >= 1
    db.close()


def test_empty_results_store_zero_rows(tmp_path):
    db_path = tmp_path / "subtake.db"
    db = ScanDatabase(db_path)
    scan_id = db.new_scan("example.com")
    assert db.save_phase1(scan_id, Phase1Result(target="example.com", generated_at="t")) == 0
    assert db.save_phase2(scan_id, Phase2Result(target="example.com", generated_at="t")) == 0
    assert db.save_phase3(
        scan_id,
        Phase3Result(target="example.com", generated_at="t",
                     summary={"total_scanned": 0, "vulnerable": 0}),
    ) == 0
    db.close()


def test_delete_removes_only_target_domain(tmp_path):
    db_path = tmp_path / "subtake.db"
    db = ScanDatabase(db_path)
    first = db.new_scan("example.com")
    db.save_phase1(first, _phase1())
    db.save_phase3(first, _phase3())
    second = db.new_scan("test.com")
    db.save_phase1(second, _phase1())

    counts = db.count_domain_records("example.com")
    assert counts == {"scans": 1, "subdomains": 2, "dns_records": 0, "findings": 1}

    removed = db.delete_domain_records("example.com")
    assert removed == {"scans": 1, "subdomains": 2, "dns_records": 0, "findings": 1}

    conn = sqlite3.connect(db_path)
    try:
        gone = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE target='example.com'"
        ).fetchone()[0]
        kept = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE target='test.com'"
        ).fetchone()[0]
        other_rows = conn.execute(
            "SELECT COUNT(*) FROM subdomains WHERE scan_id=?", (second,)
        ).fetchone()[0]
    finally:
        conn.close()
    db.close()
    assert gone == 0
    assert kept == 1
    assert other_rows == 2  # the other domain's rows are untouched


def test_delete_no_match_is_noop(tmp_path):
    db = ScanDatabase(tmp_path / "subtake.db")
    scan_id = db.new_scan("example.com")
    db.save_phase1(scan_id, _phase1())
    assert db.count_domain_records("other.com")["scans"] == 0
    assert db.delete_domain_records("other.com")["scans"] == 0
    assert db.count_domain_records("example.com")["scans"] == 1  # untouched
    db.close()
