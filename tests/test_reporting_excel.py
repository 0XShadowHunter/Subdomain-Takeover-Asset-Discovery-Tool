"""Tests for the Excel (xlsx) report format."""

from openpyxl import load_workbook

from src.models import (
    Finding,
    Phase1Result,
    Phase3Result,
    SubdomainEntry,
)
from src.reporting.reports import generate_reports, parse_formats


def _phase1():
    entry = SubdomainEntry("www.example.com")
    entry.add_source("crtsh")
    entry.add_source("bruteforce")
    return Phase1Result(
        target="example.com",
        generated_at="2026-11-23T00:00:00+00:00",
        sources_used=["crtsh", "bruteforce"],
        subdomains=[entry],
    )


def _phase3():
    return Phase3Result(
        target="example.com",
        generated_at="2026-11-23T00:00:00+00:00",
        findings=[
            Finding(
                subdomain="blog.example.com",
                type="CNAME_NXDOMAIN",
                service="unknown",
                cname_target="dead.example.github.io",
                evidence="target NXDOMAIN",
                confidence="MEDIUM",
                severity="HIGH",
                references=["https://ref.example"],
                remediation="Remove the dangling CNAME record.",
            )
        ],
        summary={"total_scanned": 1, "vulnerable": 0,
                 "by_confidence": {"HIGH": 0, "MEDIUM": 1, "LOW": 0}},
    )


def test_parse_formats_accepts_excel():
    assert parse_formats("excel") == {"excel"}
    assert "excel" in parse_formats("all")


def test_excel_report_sheets_and_cells(tmp_path):
    paths = generate_reports(
        _phase3(), tmp_path, {"excel"}, phase1=_phase1()
    )
    workbook = load_workbook(paths["excel"])
    assert workbook.sheetnames == ["Summary", "Subdomains", "Findings"]

    summary = workbook["Summary"]
    assert summary["A1"].value == "Subdomain Takeover Report"
    assert summary["B1"].value == "example.com"
    assert summary["A6"].value == "Records scanned"
    assert summary["B6"].value == 1

    subdomains = workbook["Subdomains"]
    assert subdomains["A2"].value == "example.com"
    assert subdomains["B2"].value == "www.example.com"
    assert subdomains["C2"].value == "crtsh, bruteforce"

    findings = workbook["Findings"]
    assert findings["A2"].value == "HIGH"
    assert findings["D2"].value == "blog.example.com"
    assert findings["H2"].value == "Remove the dangling CNAME record."


def test_excel_without_phase1_skips_subdomain_sheet(tmp_path):
    paths = generate_reports(_phase3(), tmp_path, {"excel"})
    workbook = load_workbook(paths["excel"])
    assert "Subdomains" not in workbook.sheetnames
    assert workbook.sheetnames == ["Summary", "Findings"]


def test_excel_is_part_of_all(tmp_path, monkeypatch):
    """--format all must include the Excel report."""
    from src.cli import main
    from src.models import Phase1Result, Phase2Result, Phase3Result

    async def fake_enum(domain, settings, skip_brute=False, wordlist=None):
        return Phase1Result(target=domain, generated_at="t", sources_used=[],
                            subdomains=[SubdomainEntry("www.example.com", ["crtsh"])])

    async def fake_resolve(
        input_path, settings, threads=None, resolvers=None, rate=None, progress_callback=None
    ):
        return Phase2Result(target="example.com", generated_at="t", records=[])

    def fake_detect(input_path, settings, fingerprints_path=None, recheck_dns=None):
        return Phase3Result(target="example.com", generated_at="t", findings=[],
                            summary={"total_scanned": 1, "vulnerable": 0,
                                     "by_confidence": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}})

    monkeypatch.setattr("src.cli.enumerate_subdomains", fake_enum)
    monkeypatch.setattr("src.cli.resolve_from_phase1", fake_resolve)
    monkeypatch.setattr("src.cli.run_detection", fake_detect)

    out = tmp_path / "out"
    rc = main(["scan", "--domain", "example.com", "--output-dir", str(out), "--format", "all"])
    assert rc == 0
    assert (out / "report.xlsx").is_file()
    workbook = load_workbook(out / "report.xlsx")
    assert "Subdomains" in workbook.sheetnames
