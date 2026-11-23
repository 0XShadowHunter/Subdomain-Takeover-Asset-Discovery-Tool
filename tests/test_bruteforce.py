"""Tests for brute-force wordlist handling and wildcard detection (DNS mocked)."""

import asyncio

from src.discovery import bruteforce
from src.discovery.dns_client import DnsAnswer, DnsStatus


def _write_wordlist(tmp_path, words):
    path = tmp_path / "words.txt"
    path.write_text("\n".join(words), encoding="utf-8")
    return path


def test_load_wordlist_dedupes_and_skips_comments(tmp_path):
    path = _write_wordlist(tmp_path, ["www", "# comment", "", "WWW", "api"])
    assert bruteforce.load_wordlist(path) == ["www", "api"]


def test_load_wordlist_missing_returns_empty(tmp_path):
    assert bruteforce.load_wordlist(tmp_path / "nope.txt") == []


def test_wildcard_hides_generic_answers(tmp_path, monkeypatch):
    path = _write_wordlist(tmp_path, ["www", "api", "dead"])
    monkeypatch.setattr(
        bruteforce, "_random_labels", lambda count, length=12: [f"probe{i}" for i in range(count)]
    )

    async def fake_resolve(resolver, name):
        if name.startswith("probe"):
            return DnsAnswer(status=DnsStatus.NOERROR, a=["10.0.0.1"])  # wildcard
        if name == "www.example.com":
            return DnsAnswer(status=DnsStatus.NOERROR, a=["10.0.0.1"])  # wildcard-only
        if name == "api.example.com":
            return DnsAnswer(status=DnsStatus.NOERROR, a=["10.0.0.99"])  # real host
        return DnsAnswer(status=DnsStatus.NXDOMAIN)

    monkeypatch.setattr(bruteforce, "resolve_name", fake_resolve)
    monkeypatch.setattr(bruteforce, "build_resolver", lambda *a, **k: object())
    found = asyncio.run(
        bruteforce.brute_force("example.com", resolvers=["1.1.1.1"], wordlist=path)
    )
    assert found == ["api.example.com"]


def test_without_wildcard_live_answers_kept(tmp_path, monkeypatch):
    path = _write_wordlist(tmp_path, ["www", "api"])
    monkeypatch.setattr(
        bruteforce, "_random_labels", lambda count, length=12: [f"probe{i}" for i in range(count)]
    )

    async def fake_resolve(resolver, name):
        if name.startswith("probe"):
            return DnsAnswer(status=DnsStatus.NXDOMAIN)  # no wildcard here
        return DnsAnswer(status=DnsStatus.NOERROR, a=["10.0.0.99"])

    monkeypatch.setattr(bruteforce, "resolve_name", fake_resolve)
    monkeypatch.setattr(bruteforce, "build_resolver", lambda *a, **k: object())
    found = asyncio.run(
        bruteforce.brute_force("example.com", resolvers=["1.1.1.1"], wordlist=path)
    )
    # asyncio.gather preserves wordlist order.
    assert found == ["www.example.com", "api.example.com"]


def test_dangling_cname_counts_as_live(tmp_path, monkeypatch):
    path = _write_wordlist(tmp_path, ["dangling"])
    monkeypatch.setattr(
        bruteforce, "_random_labels", lambda count, length=12: [f"probe{i}" for i in range(count)]
    )

    async def fake_resolve(resolver, name):
        if name.startswith("probe"):
            return DnsAnswer(status=DnsStatus.NXDOMAIN)
        # A lookup fails on the dead target, but the CNAME record exists.
        return DnsAnswer(status=DnsStatus.NOERROR, cname=["dead.example.github.io"])

    monkeypatch.setattr(bruteforce, "resolve_name", fake_resolve)
    monkeypatch.setattr(bruteforce, "build_resolver", lambda *a, **k: object())
    found = asyncio.run(
        bruteforce.brute_force("example.com", resolvers=["1.1.1.1"], wordlist=path)
    )
    assert found == ["dangling.example.com"]


def test_empty_wordlist_skips_run(tmp_path, monkeypatch):
    monkeypatch.setattr(
        bruteforce, "load_wordlist", lambda path=None: []
    )
    found = asyncio.run(
        bruteforce.brute_force("example.com", resolvers=["1.1.1.1"], wordlist=tmp_path / "x.txt")
    )
    assert found == []
