"""Phase 2 HTTP probing tests — aiohttp fully mocked."""

import asyncio
import socket

import aiohttp
import dns.resolver

from src.resolver.http_probe import DnsPythonAiohttpResolver, extract_title, probe_host


class FakeConnKey:
    """Minimal stand-in so ClientSSLError's __str__ can format."""

    host = "tls.example.com"
    port = 443
    ssl = True


class FakeContent:
    def __init__(self, body):
        self._body = body

    async def read(self, n=-1):
        if isinstance(n, int) and n > 0:
            return self._body[:n]
        return self._body


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"", url="https://x", history=()):
        self.status = status
        self.headers = headers or {}
        self._body = body
        self.url = url
        self.history = history
        self.content = FakeContent(body)

    def get_encoding(self):
        return "utf-8"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    """url -> FakeResponse | Exception; missing urls raise ClientError."""

    def __init__(self, behavior=None):
        self.behavior = dict(behavior or {})

    def get(self, url, **kwargs):
        result = self.behavior.get(url)
        if result is None:
            raise aiohttp.ClientError(f"connection refused for {url}")
        if isinstance(result, Exception):
            raise result
        return result


HTML = b"<html><head><title>  Hi   there  </title></head><body>hello</body></html>"


def test_probe_success():
    session = FakeSession(
        {
            "https://www.example.com": FakeResponse(
                200, {"Server": "GitHub.com", "X-Foo": "1"}, HTML, "https://www.example.com"
            )
        }
    )
    info = asyncio.run(probe_host(session, "www.example.com", timeout=5))
    assert info.status == 200
    assert info.title == "Hi there"
    assert info.headers["server"] == "GitHub.com"  # lowercased
    assert info.url == "https://www.example.com"
    assert info.redirects == []
    assert info.error is None
    assert "hello" in info.body_snippet


def test_body_snippet_capped_at_2kb():
    session = FakeSession(
        {"https://big.example.com": FakeResponse(200, body=b"A" * 5000, url="https://big.example.com")}
    )
    info = asyncio.run(probe_host(session, "big.example.com", timeout=5))
    assert len(info.body_snippet) <= 2048


def test_title_missing_returns_none():
    session = FakeSession(
        {"https://t.example.com": FakeResponse(404, body=b"<p>no title</p>", url="https://t.example.com")}
    )
    info = asyncio.run(probe_host(session, "t.example.com", timeout=5))
    assert info.title is None
    assert info.status == 404


def test_redirect_chain_captured():
    hop1 = FakeResponse(301, url="https://r.example.com")
    final = FakeResponse(200, body=HTML, url="https://final.example.com", history=[hop1])
    session = FakeSession({"https://r.example.com": final})
    info = asyncio.run(probe_host(session, "r.example.com", timeout=5))
    assert info.status == 200
    assert info.url == "https://final.example.com"
    assert info.redirects == ["https://r.example.com"]


def test_tls_error_kept_when_http_fallback_works():
    session = FakeSession(
        {
            "https://tls.example.com": aiohttp.ClientSSLError(
                FakeConnKey(), OSError("certificate verify failed")
            ),
            "http://tls.example.com": FakeResponse(200, body=HTML, url="http://tls.example.com"),
        }
    )
    info = asyncio.run(probe_host(session, "tls.example.com", timeout=5))
    assert info.status == 200
    assert info.error is not None
    assert "TLS" in info.error
    assert "fallback" in info.error


def test_both_schemes_fail():
    session = FakeSession({})  # every attempt raises ClientError
    info = asyncio.run(probe_host(session, "dead.example.com", timeout=5))
    assert info.status is None
    assert info.error is not None
    assert "https" in info.error and "http" in info.error


def test_timeout_captured():
    session = FakeSession(
        {
            "https://slow.example.com": asyncio.TimeoutError("timed out"),
            "http://slow.example.com": asyncio.TimeoutError("timed out"),
        }
    )
    info = asyncio.run(probe_host(session, "slow.example.com", timeout=5))
    assert info.status is None
    assert info.error is not None


def test_extract_title_variants():
    assert extract_title("<TITLE>Hello</TITLE>") == "Hello"
    assert extract_title("<title class='x'>A</title>") == "A"
    assert extract_title("<title>  spaced   out  </title>") == "spaced out"
    assert extract_title("nothing here") is None
    assert extract_title("<title></title>") is None


class FakeAddr:
    def __init__(self, address):
        self.address = address


class FakeDnsResolver:
    def __init__(self, table=None):
        self.table = dict(table or {})

    async def resolve(self, name, rdtype):
        value = self.table.get((name, rdtype))
        if value is None:
            raise dns.resolver.NoAnswer()
        if isinstance(value, Exception):
            raise value
        return value


def test_dns_python_aiohttp_resolver_matches_aiohttp_314_interface():
    dns = FakeDnsResolver(
        {
            ("www.example.com", "A"): [FakeAddr("1.2.3.4")],
            ("www.example.com", "AAAA"): [FakeAddr("2606:2800::1")],
        }
    )
    resolver = DnsPythonAiohttpResolver(dns)

    # Signature must accept (host, port, family) — aiohttp 3.14 passes family.
    both = asyncio.run(resolver.resolve("www.example.com", port=443))
    assert {info["host"] for info in both} == {"1.2.3.4", "2606:2800::1"}
    assert all(info["port"] == 443 for info in both)
    assert all(info["proto"] == socket.IPPROTO_TCP for info in both)

    v4 = asyncio.run(resolver.resolve("www.example.com", family=socket.AF_INET))
    assert {info["host"] for info in v4} == {"1.2.3.4"}

    v6 = asyncio.run(resolver.resolve("www.example.com", family=socket.AF_INET6))
    assert {info["host"] for info in v6} == {"2606:2800::1"}

    # Results are cached; failures raise OSError like a real resolver would.
    asyncio.run(resolver.resolve("www.example.com", port=8443))
    try:
        asyncio.run(resolver.resolve("dead.example.com"))
    except OSError:
        pass
    else:
        raise AssertionError("expected OSError for unresolvable host")
