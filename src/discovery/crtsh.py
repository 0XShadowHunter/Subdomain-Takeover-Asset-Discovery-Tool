"""Passive source: crt.sh (Certificate Transparency) — pure Python.

Endpoint: ``https://crt.sh/?q=%25.<domain>&output=json`` — no external binary
required (AGENT_PLAN.md §3). crt.sh is often slow or returns HTTP 501 under
load, so any failure is treated as "source unavailable" and never crashes a
run.
"""

from __future__ import annotations

import asyncio
import logging

import aiohttp

from src.discovery.passive_apis import USER_AGENT

log = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def parse_crtsh_payload(payload: object, domain: str) -> list[str]:
    """Extract matching subdomains from a crt.sh JSON response.

    Each entry's ``name_value`` may hold several SANs separated by newlines.
    Wildcards (``*.example.com``) are normalized to their base form; anything
    outside the target domain is dropped.
    """
    names: set[str] = set()
    suffix = "." + domain
    if not isinstance(payload, list):
        return []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        raw = str(entry.get("name_value", ""))
        for name in raw.split("\n"):
            name = name.strip().lower().lstrip("*. ").rstrip(".")
            if name == domain or name.endswith(suffix):
                names.add(name)
    return sorted(names)


async def fetch_from_crtsh(
    domain: str, timeout: float = 30.0, retries: int = 2, backoff: float = 2.0
) -> list[str]:
    """Return subdomain names from crt.sh, or ``[]`` after all attempts fail.

    crt.sh is frequently overloaded (HTTP 502), so each source query retries
    ``retries`` extra times with ``backoff`` seconds between attempts.
    """
    url = CRTSH_URL.format(domain=domain)
    attempts = max(1, retries + 1)
    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        for attempt in range(1, attempts + 1):
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=timeout)
                ) as resp:
                    if resp.status != 200:
                        log.warning(
                            "crt.sh attempt %d/%d returned HTTP %s for %s",
                            attempt,
                            attempts,
                            resp.status,
                            domain,
                        )
                    else:
                        payload = await resp.json(content_type=None)
                        names = parse_crtsh_payload(payload, domain)
                        log.info("crt.sh: %d names for %s", len(names), domain)
                        return names
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
                log.warning(
                    "crt.sh attempt %d/%d failed for %s: %s", attempt, attempts, domain, exc
                )
            if attempt < attempts and backoff > 0:
                await asyncio.sleep(backoff * attempt)
    return []
