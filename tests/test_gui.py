"""GUI helper tests — pure logic only, no windows are created (CI-safe)."""

import pytest

from src.gui import build_job, sort_findings_for_display
from src.models import Finding


def test_build_job_defaults(tmp_path):
    job = build_job(
        domain_raw="Example.COM",
        threads_raw="",
        timeout_raw="",
        resolvers_raw="",
        wordlist_raw="",
        output_dir_raw=str(tmp_path),
        skip_brute=True,
        formats_checked=[],
    )
    assert job["domain"] == "example.com"  # normalized
    assert job["skip_brute"] is True
    assert job["formats"] == {"html"}  # sane default when nothing ticked
    assert job["wordlist"] is None
    assert job["out_dir"] == tmp_path
    assert job["phase3_path"].name == "phase3_findings.json"


def test_build_job_applies_overrides(tmp_path):
    job = build_job(
        domain_raw="example.com",
        threads_raw="50",
        timeout_raw="7",
        resolvers_raw="1.1.1.1  9.9.9.9",
        wordlist_raw="",
        output_dir_raw=str(tmp_path),
        skip_brute=False,
        formats_checked=["html", "csv", "bogus"],  # unknown formats dropped
    )
    assert job["settings"]["general"]["concurrency"] == 50
    assert job["settings"]["general"]["timeout"] == 7.0
    assert job["settings"]["general"]["resolvers"] == ["1.1.1.1", "9.9.9.9"]
    assert job["formats"] == {"html", "csv"}


def test_build_job_rejects_ip_target(tmp_path):
    with pytest.raises(ValueError, match="IP addresses"):
        build_job(
            domain_raw="1.2.3.4",
            threads_raw="",
            timeout_raw="",
            resolvers_raw="",
            wordlist_raw="",
            output_dir_raw=str(tmp_path),
            skip_brute=False,
            formats_checked=[],
        )


def test_build_job_rejects_non_numeric_threads(tmp_path):
    with pytest.raises(ValueError, match="number"):
        build_job(
            domain_raw="example.com",
            threads_raw="abc",
            timeout_raw="",
            resolvers_raw="",
            wordlist_raw="",
            output_dir_raw=str(tmp_path),
            skip_brute=False,
            formats_checked=[],
        )


def test_build_job_rejects_non_numeric_timeout(tmp_path):
    with pytest.raises(ValueError, match="number"):
        build_job(
            domain_raw="example.com",
            threads_raw="",
            timeout_raw="soon",
            resolvers_raw="",
            wordlist_raw="",
            output_dir_raw=str(tmp_path),
            skip_brute=False,
            formats_checked=[],
        )


def test_sort_findings_for_display_is_severity_ordered():
    findings = [
        Finding(subdomain="a.example.com", type="T", severity="LOW"),
        Finding(subdomain="b.example.com", type="T", severity="HIGH"),
        Finding(subdomain="c.example.com", type="T", severity="MEDIUM"),
        Finding(subdomain="d.example.com", type="T", severity="INFO"),
    ]
    ordered = sort_findings_for_display(findings)
    assert [f.severity for f in ordered] == ["HIGH", "MEDIUM", "LOW", "INFO"]
