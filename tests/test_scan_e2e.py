"""End-to-end `scan` test — phases mocked, all file I/O + reports real (§6 AC)."""

import json

from src.cli import main


def _patch_phases(monkeypatch):
    from src.models import (
        Finding,
        HttpInfo,
        Phase1Result,
        Phase2Result,
        Phase3Result,
        ResolvedRecord,
        SubdomainEntry,
    )

    async def fake_enum(domain, settings, skip_brute=False, wordlist=None):
        return Phase1Result(
            target=domain,
            generated_at="t1",
            sources_used=["mock"],
            subdomains=[SubdomainEntry("lost.example.com", ["mock"])],
        )

    async def fake_resolve(
        input_path, settings, threads=None, resolvers=None, rate=None, progress_callback=None
    ):
        return Phase2Result(
            target="example.com",
            generated_at="t2",
            records=[
                ResolvedRecord(
                    name="lost.example.com",
                    resolved=True,
                    dns_status="NXDOMAIN",
                    cname_chain=["lost.example.com", "dead.invalid"],
                    http=HttpInfo(),
                )
            ],
        )

    def fake_detect(input_path, settings, fingerprints_path=None, recheck_dns=None):
        return Phase3Result(
            target="example.com",
            generated_at="t3",
            findings=[
                Finding(
                    subdomain="lost.example.com",
                    type="CNAME_NXDOMAIN",
                    service="unknown",
                    cname_target="dead.invalid",
                    evidence="CNAME → dead.invalid does not resolve",
                    confidence="MEDIUM",
                    severity="HIGH",
                    references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                    remediation="Remove the dangling CNAME record.",
                )
            ],
            summary={"total_scanned": 1, "vulnerable": 0,
                     "by_confidence": {"HIGH": 0, "MEDIUM": 1, "LOW": 0}},
        )

    monkeypatch.setattr("src.cli.enumerate_subdomains", fake_enum)
    monkeypatch.setattr("src.cli.resolve_from_phase1", fake_resolve)
    monkeypatch.setattr("src.cli.run_detection", fake_detect)


def test_scan_end_to_end_all_reports(tmp_path, monkeypatch):
    _patch_phases(monkeypatch)
    out = tmp_path / "out"
    rc = main(
        [
            "scan",
            "--domain",
            "Example.COM",
            "--output-dir",
            str(out),
            "--format",
            "all",
            "--skip-brute",
        ]
    )
    assert rc == 0

    # Phase contract files chained correctly
    p1 = json.loads((out / "phase1_subdomains.json").read_text(encoding="utf-8"))
    assert p1["target"] == "example.com"
    assert p1["subdomains"][0]["name"] == "lost.example.com"
    p2 = json.loads((out / "phase2_resolved.json").read_text(encoding="utf-8"))
    assert p2["records"][0]["dns_status"] == "NXDOMAIN"
    p3 = json.loads((out / "phase3_findings.json").read_text(encoding="utf-8"))
    assert p3["findings"][0]["type"] == "CNAME_NXDOMAIN"

    # JSON report mirrors the Phase 3 contract
    report_json = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report_json["summary"]["total_scanned"] == 1

    # HTML report: finding present + advisory disclaimer + ALL subdomains
    # from the scan, self-contained
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "CNAME_NXDOMAIN" in html
    assert "lost.example.com" in html
    assert "All discovered subdomains (1)" in html
    assert "Advisory" in html
    assert "<script" not in html.lower()  # self-contained: no JS

    # Markdown report
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "## Findings (1)" in md
    assert "Remove the dangling CNAME record." in md

    # CSV report (utf-8-sig) — header + 1 finding row
    csv_text = (out / "report.csv").read_text(encoding="utf-8-sig")
    lines = [line for line in csv_text.splitlines() if line]
    assert lines[0].startswith("severity,confidence,type")
    assert len(lines) == 2
    assert "CNAME_NXDOMAIN" in lines[1]


def test_scan_clean_target_has_empty_reports(tmp_path, monkeypatch):
    from src.models import (
        HttpInfo,
        Phase1Result,
        Phase2Result,
        Phase3Result,
        ResolvedRecord,
        SubdomainEntry,
    )

    async def fake_enum(domain, settings, skip_brute=False, wordlist=None):
        return Phase1Result(
            target=domain, generated_at="t1", sources_used=["mock"],
            subdomains=[SubdomainEntry("www.example.com", ["mock"])],
        )

    async def fake_resolve(
        input_path, settings, threads=None, resolvers=None, rate=None, progress_callback=None
    ):
        return Phase2Result(
            target="example.com", generated_at="t2",
            records=[ResolvedRecord(
                name="www.example.com", resolved=True, dns_status="NOERROR",
                a=["93.184.216.34"], http=HttpInfo(status=200, title="Example Domain"),
            )],
        )

    def fake_detect(input_path, settings, fingerprints_path=None, recheck_dns=None):
        return Phase3Result(
            target="example.com", generated_at="t3", findings=[],
            summary={"total_scanned": 1, "vulnerable": 0,
                     "by_confidence": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}},
        )

    monkeypatch.setattr("src.cli.enumerate_subdomains", fake_enum)
    monkeypatch.setattr("src.cli.resolve_from_phase1", fake_resolve)
    monkeypatch.setattr("src.cli.run_detection", fake_detect)

    out = tmp_path / "out"
    rc = main(["scan", "--domain", "example.com", "--output-dir", str(out), "--format", "html"])
    assert rc == 0
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "No takeover findings" in html


def test_scan_invalid_format(tmp_path):
    rc = main(
        [
            "scan",
            "--domain",
            "example.com",
            "--output-dir",
            str(tmp_path / "o"),
            "--format",
            "bogus",
        ]
    )
    assert rc == 2


def test_scan_invalid_domain(tmp_path):
    assert main(["scan", "--domain", "1.2.3.4"]) == 2


def test_scan_reports_subset_only(tmp_path, monkeypatch):
    _patch_phases(monkeypatch)
    out = tmp_path / "out"
    rc = main(
        ["scan", "--domain", "example.com", "--output-dir", str(out), "--format", "csv,markdown"]
    )
    assert rc == 0
    assert (out / "report.csv").is_file()
    assert (out / "report.md").is_file()
    assert not (out / "report.html").exists()
    assert not (out / "report.json").exists()
