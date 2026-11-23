"""Tests for domain input validation (pure logic — no network)."""

import pytest

from src.discovery.validators import InvalidDomainError, normalize_domain


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("https://blog.example.com/path", "blog.example.com"),
        ("http://example.com:8080", "example.com"),
        ("example.com:443", "example.com"),
        ("example.com.", "example.com"),
        ("  example.com  ", "example.com"),
        ("user:pass@host.example.com", "host.example.com"),
        ("sub.blog.example.co.uk", "sub.blog.example.co.uk"),
        ("https://Example.COM/", "example.com"),
    ],
)
def test_valid_domains(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        None,
        "1.2.3.4",
        "255.255.255.255",
        "::1",
        "[2001:db8::1]",
        "no_tld",
        "not a domain",
        "exa mple.com",
        "-bad.com",
        "bad-.com",
        "exa_mple.com",
        "example..com",
        "http://",
        "http://1.2.3.4",
    ],
)
def test_invalid_domains(raw):
    with pytest.raises(InvalidDomainError):
        normalize_domain(raw)


def test_error_message_mentions_input():
    with pytest.raises(InvalidDomainError, match="1.2.3.4"):
        normalize_domain("1.2.3.4")
