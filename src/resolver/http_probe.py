"""Phase 2 HTTP/HTTPS probing (pure Python via aiohttp).

- DNS inside aiohttp goes through ``DnsPythonAiohttpResolver`` — the same
  configured resolver list as the DNS layer, never the OS resolver config —
  so HTTP probing behaves identically on Windows and Linux.
- Captures: final URL, redirect chain, status, title, headers, first 2KB of
  the body, and errors (TLS errors on the https attempt are preserved).
- https is tried first; on failure http is attempted as a fallback.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket

import aiohttp
import dns.exception
import dns.resolver

from src.discovery.passive_apis import USER_AGENT
from src.models import HttpInfo

log = logging.getLogger(__name__)

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
BODY_SNIPPET_BYTES = 2048
TITLE_MAX_CHARS = 200


class DnsPythonAiohttpResolver(aiohttp.abc.AbstractResolver):
    """aiohttp connector resolver backed by a dnspython resolver instance.

    Results are cached per host for the lifetime of the scan (a host is
    typically contacted twice: https + fallback).
    """

    def __init__(self, resolver):
        self._resolver = resolver
        self._cache: dict[str, list[dict]] = {}

    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        """Match aiohttp ≥3.14's AbstractResolver.resolve(host, port, family).

        The connector may ask for a specific address family (AF_INET for
        https, AF_INET6 for AAAA-only attempts); filtering happens at return
        time so one cache entry serves every family.
        """
        if host not in self._cache:
            self._cache[host] = await self._lookup(host)
        infos = self._cache[host]
        if not infos:
            raise OSError(f"cannot resolve {host} via the configured resolvers")
        return [
            dict(info, port=port)
            for info in infos
            if family in (socket.AF_UNSPEC, info["family"])
        ]

    async def _lookup(self, host) -> list[dict]:
        results: list[dict] = []
        for rdtype, family in (("A", socket.AF_INET), ("AAAA", socket.AF_INET6)):
            try:
                resp = await self._resolver.resolve(host, rdtype)
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.exception.Timeout,
                dns.resolver.NoNameservers,
                OSError,
            ):
                continue
            for rdata in resp:
                results.append(
                    {
                        "hostname": host,
                        "host": rdata.address,
                        "port": 0,
                        "family": family,
                        "proto": socket.IPPROTO_TCP,
                        "flags": socket.AI_NUMERICHOST,
                    }
                )
        return results

    async def close(self):
        self._cache.clear()


def extract_title(html: str) -> str | None:
    """Pull the <title> from an HTML snippet; None when absent/empty."""
    match = TITLE_RE.search(html)
    if not match:
        return None
    title = " ".join(match.group(1).split())  # collapse whitespace
    return title[:TITLE_MAX_CHARS] or None


async def _attempt(session: aiohttp.ClientSession, url: str, timeout: float) -> HttpInfo:
    """One scheme attempt; raises on transport errors (caller does fallback)."""
    async with session.get(
        url,
        timeout=aiohttp.ClientTimeout(total=timeout),
        allow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    ) as resp:
        raw = await resp.content.read(BODY_SNIPPET_BYTES)
        try:
            encoding = resp.get_encoding()
        except (LookupError, UnicodeDecodeError):
            encoding = "utf-8"
        snippet = raw.decode(encoding, errors="replace")
        return HttpInfo(
            url=str(resp.url),
            status=resp.status,
            title=extract_title(snippet),
            body_snippet=snippet,
            headers={k.lower(): v for k, v in resp.headers.items()},
            redirects=[str(h.url) for h in resp.history],
        )


async def probe_host(
    session: aiohttp.ClientSession, name: str, timeout: float
) -> HttpInfo:
    """Probe https then http for one host; always returns an HttpInfo."""
    https_url = f"https://{name}"
    tls_error: str | None = None
    try:
        return await _attempt(session, https_url, timeout)
    except asyncio.TimeoutError as exc:
        # Caught first: aiohttp's ServerTimeoutError inherits from both
        # asyncio.TimeoutError and ClientError.
        first_error = f"https: {exc}"
    except aiohttp.ClientSSLError as exc:
        tls_error = f"TLS error: {exc}"
        first_error = f"https: {tls_error}"
    except (aiohttp.ClientError, OSError) as exc:
        first_error = f"https: {exc}"

    try:
        info = await _attempt(session, f"http://{name}", timeout)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        return HttpInfo(url=https_url, error=f"{first_error}; http: {exc}")

    if tls_error:
        info.error = f"{tls_error} (http fallback succeeded)"
    log.debug("HTTP probe %s -> %s", name, info.status)
    return info
