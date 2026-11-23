"""Extra passive OSINT sources — pure Python HTTP, no API keys required.

Hackertarget (hostsearch) and RapidDNS complement crt.sh so a scan keeps
finding assets even when crt.sh is overloaded (it frequently answers 502).
Both sources degrade gracefully — any failure yields ``[]`` plus a warning,
exactly like the rest of the discovery stack.
"""

from __future__ import annotations

import asyncio
import logging
import re

import aiohttp

log = logging.getLogger(__name__)

#: A polite, identifiable UA — default python-aiohttp UAs are often blocked.
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) subtake/0.1"


def _clean_name(raw: str, domain: str) -> str | None:
    """Normalize one candidate name; keep it only when inside the target zone."""
    name = raw.strip().lower().lstrip("*. ").rstrip(".").strip()
    if not name:
        return None
    if name == domain or name.endswith("." + domain):
        return name
    return None


async def fetch_from_hackertarget(domain: str, timeout: float = 25.0) -> list[str]:
    """api.hackertarget.com/hostsearch — plain-text ``subdomain,IP`` lines."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status != 200:
                    log.warning(
                        "hackertarget returned HTTP %s for %s — skipping", resp.status, domain
                    )
                    return []
                text = await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        log.warning("hackertarget query failed for %s: %s", domain, exc)
        return []

    names: set[str] = set()
    for line in text.splitlines():
        cleaned = _clean_name(line.split(",")[0], domain)
        if cleaned:
            names.add(cleaned)
    log.info("hackertarget: %d names for %s", len(names), domain)
    return sorted(names)


async def fetch_from_rapiddns(domain: str, timeout: float = 25.0) -> list[str]:
    """rapiddns.io subdomain listing (?full=1) — parse names out of the HTML."""
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status != 200:
                    log.warning(
                        "rapiddns returned HTTP %s for %s — skipping", resp.status, domain
                    )
                    return []
                text = (await resp.text()).lower()
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        log.warning("rapiddns query failed for %s: %s", domain, exc)
        return []

    # Match candidate names only at token boundaries so "notexample.com" never
    # matches a search for "example.com".
    pattern = re.compile(
        r"(?<![a-z0-9._-])[a-z0-9_*.-]+\." + re.escape(domain.lower())
    )
    names: set[str] = set()
    for match in pattern.finditer(text):
        cleaned = _clean_name(match.group(0), domain)
        if cleaned:
            names.add(cleaned)
    log.info("rapiddns: %d names for %s", len(names), domain)
    return sorted(names)
