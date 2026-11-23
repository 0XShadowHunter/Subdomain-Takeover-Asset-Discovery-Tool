"""Phase 2 pipeline tests — DNS/HTTP mocked at function level, JSON I/O real."""

import asyncio
import json

import pytest

from src.discovery.dns_client import DnsStatus
from src.models import HttpInfo, ResolvedRecord
from src.resolver import pipeline
from src.resolver.pipeline import Phase2InputError, load_phase1_file, resolve_from_phase1


def _write_phase1(tmp_path, names, target="example.com"):
    path = tmp_path / "phase1.json"
    path.write_text(
        json.dumps(
            {
                "target": target,
                "generated_at": "now",
                "sources_used": ["crtsh"],
                "subdomains": [{"name": n, "sources": ["crtsh"]} for n in names],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_load_phase1_drops_invalid_names(tmp_path):
    path = _write_phase1(tmp_path, ["www.example.com", "bad name!", "api.example.com"])
    result = load_phase1_file(path)
    assert result.target == "example.com"
    assert [entry.name for entry in result.subdomains] == [
        "www.example.com",
        "api.example.com",
    ]


def test_load_phase1_missing_file(tmp_path):
    with pytest.raises(Phase2InputError):
        load_phase1_file(tmp_path / "nope.json")


def test_load_phase1_bad_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(Phase2InputError):
        load_phase1_file(path)


def test_load_phase1_wrong_shape(tmp_path):
    path = tmp_path / "wrong.json"
    path.write_text(json.dumps({"hello": 1}), encoding="utf-8")
    with pytest.raises(Phase2InputError):
        load_phase1_file(path)


def test_pipeline_covers_all_names_in_order(tmp_path, monkeypatch):
    path = _write_phase1(
        tmp_path, ["www.example.com", "dangling.example.com", "dead.example.com"]
    )

    async def fake_resolve_record(resolver, name, max_depth=10):
        if name.startswith("www"):
            return ResolvedRecord(
                name=name, resolved=True, dns_status=DnsStatus.NOERROR, a=["1.2.3.4"]
            )
        if name.startswith("dangling"):
            return ResolvedRecord(
                name=name,
                resolved=True,
                dns_status=DnsStatus.NXDOMAIN,
                cname_chain=[name, "dead.github.io"],
            )
        return ResolvedRecord(name=name, resolved=False, dns_status=DnsStatus.NXDOMAIN)

    async def fake_probe(session, name, timeout):
        return HttpInfo(url=f"https://{name}", status=404, title="nope")

    monkeypatch.setattr(pipeline, "resolve_record", fake_resolve_record)
    monkeypatch.setattr(pipeline, "probe_host", fake_probe)

    result = asyncio.run(
        resolve_from_phase1(
            path,
            settings={"general": {"resolvers": ["1.1.1.1"], "timeout": 5, "concurrency": 10}},
        )
    )
    assert result.target == "example.com"
    assert [r.name for r in result.records] == [
        "www.example.com",
        "dangling.example.com",
        "dead.example.com",
    ]
    by_name = {r.name: r for r in result.records}
    assert by_name["www.example.com"].http.status == 404  # resolved → probed
    assert by_name["dangling.example.com"].http.status == 404  # dangling → probed too
    assert by_name["dead.example.com"].http.status is None  # unresolved → skipped


def test_pipeline_survives_unexpected_errors(tmp_path, monkeypatch):
    path = _write_phase1(tmp_path, ["boom.example.com"])

    async def fake_resolve_record(resolver, name, max_depth=10):
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(pipeline, "resolve_record", fake_resolve_record)

    result = asyncio.run(
        resolve_from_phase1(
            path,
            settings={"general": {"resolvers": ["1.1.1.1"], "timeout": 5, "concurrency": 10}},
        )
    )
    assert len(result.records) == 1
    record = result.records[0]
    assert record.name == "boom.example.com"
    assert record.dns_status == DnsStatus.SERVFAIL
    assert record.http.error is not None


def test_pipeline_empty_input_returns_empty_result(tmp_path):
    path = _write_phase1(tmp_path, [])
    result = asyncio.run(
        resolve_from_phase1(
            path,
            settings={"general": {"resolvers": ["1.1.1.1"], "timeout": 5, "concurrency": 10}},
        )
    )
    assert result.records == []
    assert result.target == "example.com"
