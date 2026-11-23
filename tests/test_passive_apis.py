"""Tests for the extra passive OSINT sources — network fully mocked."""

import asyncio

import aiohttp

from src.discovery.passive_apis import (
    fetch_from_hackertarget,
    fetch_from_rapiddns,
)

HACKERTARGET_TEXT = (
    "blog.example.com,1.2.3.4\n"
    "WWW.example.com,1.2.3.5\n"
    "*.example.com,1.2.3.6\n"
    "other.site,9.9.9.9\n"
    "\n"
)


class FakeResponse:
    def __init__(self, status=200, text=""):
        self.status = status
        self._text = text

    async def text(self):
        if isinstance(self._text, Exception):
            raise self._text
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    def __init__(self, response, headers=None):
        self._response = response
        self.headers_seen = headers

    def get(self, url, timeout=None, headers=None):
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _install(monkeypatch, response):
    """Patch ClientSession; returns the constructor kwargs actually used."""
    created: dict = {}

    def factory(**kwargs):
        created.update(kwargs)
        created["session"] = FakeSession(response, **kwargs)
        return created["session"]

    monkeypatch.setattr(aiohttp, "ClientSession", factory)
    return created


def test_hackertarget_parses_and_filters(monkeypatch):
    created = _install(monkeypatch, FakeResponse(200, HACKERTARGET_TEXT))
    names = asyncio.run(fetch_from_hackertarget("example.com", timeout=1))
    # "*.example.com" normalizes to the apex — consistent with the crt.sh parser.
    assert names == ["blog.example.com", "example.com", "www.example.com"]
    headers = created.get("headers")
    assert headers and "User-Agent" in headers


def test_hackertarget_non_200_returns_empty(monkeypatch):
    _install(monkeypatch, FakeResponse(429, "rate limited"))
    assert asyncio.run(fetch_from_hackertarget("example.com")) == []


def test_hackertarget_error_returns_empty(monkeypatch):
    _install(monkeypatch, FakeResponse(200, aiohttp.ClientError("boom")))
    assert asyncio.run(fetch_from_hackertarget("example.com")) == []


def test_rapiddns_extracts_names_from_html(monkeypatch):
    html = (
        "<table><tr><td>2008.udemy.example.com</td></tr>"
        "<tr><td>blog.example.com</td></tr>"
        "<tr><td>notexample.com</td></tr>"  # must NOT match (token boundary)
        "<tr><td>*.mail.example.com</td></tr>"
        "</table>"
    )
    # NOTE: the target here is a subdomain-bearing zone to exercise boundaries.
    created = _install(monkeypatch, FakeResponse(200, html.replace("udemy.", "")))
    names = asyncio.run(fetch_from_rapiddns("example.com", timeout=1))
    assert names == ["2008.example.com", "blog.example.com", "mail.example.com"]
    headers = created.get("headers")
    assert headers and "User-Agent" in headers


def test_rapiddns_non_200_returns_empty(monkeypatch):
    _install(monkeypatch, FakeResponse(403, "forbidden"))
    assert asyncio.run(fetch_from_rapiddns("example.com")) == []


def test_rapiddns_error_returns_empty(monkeypatch):
    _install(monkeypatch, FakeResponse(200, aiohttp.ClientError("boom")))
    assert asyncio.run(fetch_from_rapiddns("example.com")) == []
