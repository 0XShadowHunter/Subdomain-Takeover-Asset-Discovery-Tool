"""Tests for the shared data contracts (AGENT_PLAN.md §2) — JSON round-trips."""

import json

from src.models import (
    Finding,
    HttpInfo,
    Phase1Result,
    Phase2Result,
    Phase3Result,
    ResolvedRecord,
    SubdomainEntry,
)
from src.utils.paths import dump_json, read_json


def test_subdomain_entry_add_source_dedupes():
    entry = SubdomainEntry("www.example.com")
    entry.add_source("crtsh")
    entry.add_source("crtsh")
    entry.add_source("")
    assert entry.sources == ["crtsh"]


def test_phase1_contract_roundtrip(tmp_path):
    result = Phase1Result(
        target="example.com",
        generated_at="2026-11-22T00:00:00+00:00",
        sources_used=["crtsh"],
        subdomains=[SubdomainEntry("blog.example.com", ["crtsh", "bruteforce"])],
    )
    path = dump_json(result.to_dict(), tmp_path / "phase1.json")
    raw = json.loads(path.read_text(encoding="utf-8"))
    # Exact contract keys (AGENT_PLAN.md §2)
    assert set(raw) == {"target", "generated_at", "sources_used", "subdomains"}
    assert set(raw["subdomains"][0]) == {"name", "sources"}

    restored = Phase1Result.from_dict(read_json(path))
    assert restored.target == "example.com"
    assert restored.subdomains[0].name == "blog.example.com"
    assert restored.subdomains[0].sources == ["crtsh", "bruteforce"]


def test_phase2_contract_roundtrip(tmp_path):
    record = ResolvedRecord(
        name="blog.example.com",
        resolved=True,
        dns_status="NOERROR",
        a=["1.2.3.4"],
        cname_chain=["blog.example.com", "example.github.io"],
        http=HttpInfo(
            url="https://blog.example.com", status=404, title="Site not found"
        ),
    )
    path = dump_json(
        Phase2Result(target="example.com", generated_at="t", records=[record]).to_dict(),
        tmp_path / "phase2.json",
    )
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert set(raw["records"][0]) == {
        "name",
        "resolved",
        "dns_status",
        "a",
        "aaaa",
        "cname_chain",
        "ns",
        "http",
    }
    assert set(raw["records"][0]["http"]) == {
        "url",
        "status",
        "title",
        "body_snippet",
        "headers",
        "redirects",
        "error",
    }

    restored = Phase2Result.from_dict(read_json(path))
    assert restored.records[0].http.title == "Site not found"
    assert restored.records[0].cname_chain[-1] == "example.github.io"


def test_phase3_contract_roundtrip(tmp_path):
    finding = Finding(
        subdomain="blog.example.com",
        type="CNAME_FINGERPRINT",
        service="GitHub Pages",
        cname_target="example.github.io",
        evidence="Matched fingerprint",
        confidence="HIGH",
        severity="CRITICAL",
        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
        remediation="Remove the dangling CNAME record or reclaim the resource.",
    )
    path = dump_json(
        Phase3Result(
            target="example.com",
            generated_at="t",
            findings=[finding],
            summary={"total_scanned": 1},
        ).to_dict(),
        tmp_path / "phase3.json",
    )
    restored = Phase3Result.from_dict(read_json(path))
    assert restored.findings[0].service == "GitHub Pages"
    assert restored.findings[0].confidence == "HIGH"
    assert restored.summary["total_scanned"] == 1


def test_from_dict_tolerates_missing_keys():
    result = Phase1Result.from_dict({"target": "example.com"})
    assert result.subdomains == []
    assert result.sources_used == []
    record = ResolvedRecord.from_dict({"name": "x.example.com"})
    assert record.resolved is False
    assert record.http.status is None
