"""Tests for source merging/normalization (pure logic — no network)."""

from src.discovery.pipeline import merge_results


def test_merge_normalizes_dedupes_and_tags():
    result = merge_results(
        "example.com",
        {
            "crtsh": ["WWW.example.com", "*.blog.example.com", "evil.example.org"],
            "bruteforce": ["www.example.com", "blog.example.com"],
            "subfinder": [],
        },
    )
    assert result.target == "example.com"
    assert result.sources_used == ["bruteforce", "crtsh", "subfinder"]
    by_name = {entry.name: entry.sources for entry in result.subdomains}
    assert by_name == {
        "www.example.com": ["crtsh", "bruteforce"],
        "blog.example.com": ["crtsh", "bruteforce"],
    }


def test_merge_keeps_apex_when_reported():
    result = merge_results("example.com", {"crtsh": ["example.com"]})
    assert [entry.name for entry in result.subdomains] == ["example.com"]


def test_merge_drops_out_of_scope_names():
    result = merge_results(
        "example.com", {"subfinder": ["other.org", "sub.evil.example.com.evil.org"]}
    )
    assert result.subdomains == []


def test_merge_strips_wildcards_and_trailing_dots():
    result = merge_results("example.com", {"crtsh": ["*.mail.example.com.", "WWW.Example.COM"]})
    names = [entry.name for entry in result.subdomains]
    assert names == ["mail.example.com", "www.example.com"]


def test_merge_empty_input():
    result = merge_results("example.com", {})
    assert result.subdomains == []
    assert result.sources_used == []
