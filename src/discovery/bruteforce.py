"""Active source: wordlist brute-force with async DNS and wildcard detection.

Wildcard handling (acceptance criterion: "Wildcard DNS domains do not flood
the result"):
- Probe N random labels (default 3); if they all resolve, the domain is a
  wildcard and their A/CNAME values become the wildcard signature.
- Candidates whose A/CNAME values are entirely contained in that signature
  are dropped — they only prove the wildcard, not a real host.
"""

from __future__ import annotations

import asyncio
import logging
import random
import string
from pathlib import Path

from src.discovery.dns_client import DnsAnswer, DnsStatus, build_resolver, resolve_name
from src.utils.paths import DEFAULT_WORDLIST

log = logging.getLogger(__name__)


def load_wordlist(path: Path | None = None) -> list[str]:
    """Read a wordlist (UTF-8), skipping blanks/comments; deduped, lowercase."""
    wordlist_path = path if path is not None else DEFAULT_WORDLIST
    if not wordlist_path.is_file():
        log.warning("Wordlist not found: %s — brute-force skipped", wordlist_path)
        return []
    words: list[str] = []
    seen: set[str] = set()
    for line in wordlist_path.read_text(encoding="utf-8").splitlines():
        word = line.strip().lower()
        if word and not word.startswith("#") and word not in seen:
            seen.add(word)
            words.append(word)
    return words


def _random_labels(count: int, length: int = 12) -> list[str]:
    """Random labels unlikely to exist on any real DNS zone."""
    alphabet = string.ascii_lowercase + string.digits
    return ["".join(random.choices(alphabet, k=length)) for _ in range(count)]


async def detect_wildcard(
    resolver, domain: str, probe_count: int = 3
) -> tuple[bool, set[str]]:
    """Probe random labels; return (is_wildcard, signature_values)."""
    signature: set[str] = set()
    resolved_count = 0
    for label in _random_labels(probe_count):
        answer = await resolve_name(resolver, f"{label}.{domain}")
        if answer.resolved:
            resolved_count += 1
            signature.update(answer.a)
            signature.update(answer.cname)
    is_wildcard = probe_count > 0 and resolved_count == probe_count and bool(signature)
    if is_wildcard:
        log.warning(
            "Wildcard DNS detected for %s (signature: %s)", domain, sorted(signature)
        )
    return is_wildcard, signature


async def brute_force(
    domain: str,
    resolvers: list[str],
    timeout: float = 10.0,
    concurrency: int = 100,
    wordlist: Path | None = None,
    probe_count: int = 3,
) -> list[str]:
    """Resolve every candidate word; return names that really resolve."""
    words = load_wordlist(wordlist)
    if not words:
        return []
    resolver = build_resolver(resolvers, timeout=timeout)
    is_wildcard, signature = await detect_wildcard(resolver, domain, probe_count)

    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def check(word: str) -> tuple[str, DnsAnswer]:
        async with semaphore:
            return word, await resolve_name(resolver, f"{word}.{domain}")

    results = await asyncio.gather(*(check(word) for word in words))

    found: list[str] = []
    for word, answer in results:
        if answer.status != DnsStatus.NOERROR:
            continue
        values = set(answer.a) | set(answer.cname)
        if is_wildcard and values and values <= signature:
            continue  # generic wildcard answer — not a real host
        found.append(f"{word}.{domain}")
    log.info(
        "Brute-force: %d/%d candidates resolve for %s", len(found), len(words), domain
    )
    return found
