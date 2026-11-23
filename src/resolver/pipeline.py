"""Phase 2 pipeline: phase1_subdomains.json → resolve DNS + HTTP → contract.

- Reads and validates the Phase 1 file (re-validates every name; malformed
  names are skipped with a warning).
- Resolves each subdomain with the configured resolver list (never the OS
  resolver config), follows full CNAME chains with loop protection, and probes
  HTTP/HTTPS for records that resolve (dangling CNAMEs are probed too — park
  pages are valuable evidence for Phase 3).
- Every failure is captured per record; one bad host can never crash a scan.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

from src.discovery.dns_client import DnsStatus, build_resolver
from src.discovery.validators import normalize_domain
from src.models import HttpInfo, Phase1Result, Phase2Result, ResolvedRecord
from src.resolver.dns_resolver import MAX_CHAIN_DEPTH, resolve_record
from src.resolver.http_probe import DnsPythonAiohttpResolver, probe_host
from src.resolver.rate_limit import RateLimiter
from src.utils.paths import read_json

log = logging.getLogger(__name__)

#: Fallback resolver list (kept in sync with paths.DEFAULT_RESOLVERS).
FALLBACK_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


class Phase2InputError(ValueError):
    """Raised when the Phase 1 input file is missing or not a valid contract."""


def load_phase1_file(path: Path) -> Phase1Result:
    """Read and validate a Phase 1 contract file; raises Phase2InputError."""
    path = Path(path)
    if not path.is_file():
        raise Phase2InputError(f"Input file not found: {path}")
    try:
        data = read_json(path)
    except (OSError, ValueError) as exc:  # ValueError covers JSONDecodeError
        raise Phase2InputError(f"Cannot parse {path} as JSON: {exc}") from exc
    if not isinstance(data, dict) or not data.get("target"):
        raise Phase2InputError(f"{path} is not a phase1_subdomains.json contract file")
    result = Phase1Result.from_dict(data)
    try:
        result.target = normalize_domain(result.target)
    except ValueError as exc:
        raise Phase2InputError(
            f"Invalid target in input file: {result.target!r}"
        ) from exc
    valid: list = []
    for entry in result.subdomains:
        try:
            entry.name = normalize_domain(entry.name)
        except ValueError:
            log.warning("Skipping invalid subdomain name in input: %r", entry.name)
            continue
        valid.append(entry)
    result.subdomains = valid
    return result


async def resolve_from_phase1(
    input_path: Path,
    settings: dict,
    threads: int | None = None,
    resolvers: list[str] | None = None,
    rate: float | None = None,
    progress_callback: Callable[[int], None] | None = None,
) -> Phase2Result:
    """Resolve + probe every Phase 1 subdomain and build the Phase 2 result."""
    phase1 = load_phase1_file(input_path)
    names = [entry.name for entry in phase1.subdomains]
    if not names:
        log.warning("Phase 1 input contains no subdomains — nothing to resolve")

    general = settings.get("general", {})
    resolver_list = [str(r) for r in (resolvers or general.get("resolvers", FALLBACK_RESOLVERS))]
    timeout = float(general.get("timeout", 10))
    concurrency = max(1, int(threads or general.get("concurrency", 100)))
    dns_resolver = build_resolver(resolver_list, timeout=timeout)
    limiter = RateLimiter(float(rate) if rate else 0)
    semaphore = asyncio.Semaphore(concurrency)
    progress_callback = progress_callback or (lambda _n: None)

    records: list[ResolvedRecord | None] = [None] * len(names)

    # HTTP DNS lookups go through the same configured resolver list.
    connector = aiohttp.TCPConnector(resolver=DnsPythonAiohttpResolver(dns_resolver))
    async with aiohttp.ClientSession(connector=connector) as session:

        async def process(index: int, name: str):
            async with semaphore:
                try:
                    record = await resolve_record(dns_resolver, name, MAX_CHAIN_DEPTH)
                    if record.resolved:
                        await limiter.acquire()
                        record.http = await probe_host(session, name, timeout)
                except Exception as exc:  # noqa: BLE001 — safety net for one host
                    log.warning("Unexpected failure on %s: %s", name, exc)
                    record = ResolvedRecord(
                        name=name,
                        dns_status=DnsStatus.SERVFAIL,
                        http=HttpInfo(error=str(exc)),
                    )
                progress_callback(index + 1)
                return index, record

        tasks = [asyncio.create_task(process(index, name)) for index, name in enumerate(names)]
        for future in asyncio.as_completed(tasks):
            index, record = await future
            records[index] = record

    return Phase2Result(
        target=phase1.target,
        generated_at=datetime.now(timezone.utc).isoformat(),
        records=[record for record in records if record is not None],
    )
