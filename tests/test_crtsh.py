"""Tests for crt.sh parsing and fetching — network fully mocked."""

import asyncio

import aiohttp

from src.discovery.crtsh import fetch_from_crtsh, parse_crtsh_payload

SAMPLE = [
    {"name_value": "blog.example.com\nwww.example.com"},
    {"name_value": "*.example.com"},
    {"name_value": "mail.example.com\r"},
    {"name_value": "other.site"},
    {"common_name": "ignored.example.com"},  # no name_value -> ignored
    {},
]


def test_parse_extracts_and_filters():
    names = parse_crtsh_payload(SAMPLE, "example.com")
    assert names == [
        "blog.example.com",
        "example.com",
        "mail.example.com",
        "www.example.com",
    ]


def test_parse_handles_none_and_garbage():
    assert parse_crtsh_payload(None, "example.com") == []
    assert parse_crtsh_payload({"oops": 1}, "example.com") == []


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status = status
        self._payload = payload

    async def json(self, content_type=None):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    def __init__(self, response):
        self._response = response
        self.calls = 0

    def get(self, url, timeout=None, headers=None):
        self.calls += 1
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _install(monkeypatch, response):
    session = FakeSession(response)
    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kwargs: session)
    return session


def test_fetch_success(monkeypatch):
    session = _install(monkeypatch, FakeResponse(200, SAMPLE))
    names = asyncio.run(fetch_from_crtsh("example.com", timeout=1, retries=0))
    assert "www.example.com" in names
    assert "other.site" not in names
    assert session.calls == 1  # retries=0 → exactly one attempt


def test_fetch_retries_then_succeeds(monkeypatch):
    # 502 on the first attempt (crt.sh's classic overload), success on retry —
    # the whole point of the retry loop.
    session = FakeSessionMulti([FakeResponse(502, None), FakeResponse(200, SAMPLE)])
    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kwargs: session)
    names = asyncio.run(
        fetch_from_crtsh("example.com", timeout=1, retries=1, backoff=0)
    )
    assert "www.example.com" in names
    assert session.calls == 2


class FakeSessionMulti(FakeSession):
    """Returns queued responses in order, repeating the last one."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def get(self, url, timeout=None, headers=None):
        response = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return response


def test_fetch_retries_exhausted_returns_empty(monkeypatch):
    session = FakeSessionMulti(
        [FakeResponse(502, None), FakeResponse(502, None), FakeResponse(502, None)]
    )
    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kwargs: session)
    names = asyncio.run(
        fetch_from_crtsh("example.com", timeout=1, retries=2, backoff=0)
    )
    assert names == []
    assert session.calls == 3  # 1 + 2 retries


def test_fetch_non_200_returns_empty(monkeypatch):
    _install(monkeypatch, FakeResponse(501, None))
    assert asyncio.run(fetch_from_crtsh("example.com", retries=0)) == []


def test_fetch_bad_json_returns_empty(monkeypatch):
    _install(monkeypatch, FakeResponse(200, ValueError("not JSON")))
    assert asyncio.run(fetch_from_crtsh("example.com", retries=0)) == []


def test_fetch_network_error_returns_empty(monkeypatch):
    _install(monkeypatch, FakeResponse(200, aiohttp.ClientError("boom")))
    assert asyncio.run(fetch_from_crtsh("example.com", retries=0)) == []
