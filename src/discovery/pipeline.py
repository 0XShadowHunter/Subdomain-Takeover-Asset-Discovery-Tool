"""Phase 1 pipeline: run every source, merge, normalize, produce the contract.

Sources:
- crt.sh                      (pure Python, always available)
- subfinder / amass / assetfinder (optional binaries — skipped with a warning)
- wordlist brute-force        (async DNS + wildcard detection)

Output: data/output/phase1_subdomains.json (AGENT_PLAN.md §2 contract).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path

from src.discovery import bruteforce, crtsh, external_tools, passive_apis
from src.models import Phase1Result, SubdomainEntry
from src.utils.paths import PROJECT_ROOT
from src.utils.platform import find_tool

log = logging.getLogger(__name__)

#: (tool name, runner function, default timeout in seconds)
_EXTERNAL_SOURCES: tuple[tuple[str, object, float], ...] = (
    ("subfinder", external_tools.run_subfinder, 60),
    ("amass", external_tools.run_amass, 120),
    ("assetfinder", external_tools.run_assetfinder, 60),
)


def merge_results(domain: str, source_results: dict[str, list[str]]) -> Phase1Result:
    """Normalize (lowercase, strip wildcards), dedupe, and tag with sources.

    Only names inside the target zone survive: the apex itself or anything
    ending with ``.<domain>``. ``sources_used`` lists every source that ran,
    even when it returned nothing.
    """
    merged: dict[str, SubdomainEntry] = {}
    for source, names in source_results.items():
        for raw in names:
            name = str(raw).strip().lower().lstrip("*. ").rstrip(".")
            if not name:
                continue
            if name != domain and not name.endswith("." + domain):
                continue  # out-of-scope noise from external tools
            entry = merged.setdefault(name, SubdomainEntry(name=name))
            entry.add_source(source)
    entries = sorted(merged.values(), key=lambda e: e.name)
    log.info(
        "Merged %d unique subdomains from %d source(s)", len(entries), len(source_results)
    )
    return Phase1Result(
        target=domain,
        generated_at=datetime.now(timezone.utc).isoformat(),
        sources_used=sorted(source_results.keys()),
        subdomains=entries,
    )


async def enumerate_subdomains(
    domain: str,
    settings: dict,
    skip_brute: bool = False,
    wordlist: Path | None = None,
) -> Phase1Result:
    """Run all enabled sources for ``domain`` and merge into Phase1Result."""
    general = settings.get("general", {})
    sources_cfg = settings.get("sources", {})
    source_results: dict[str, list[str]] = {}

    # --- crt.sh (pure Python; retries soften its frequent HTTP 502s) ---
    crtsh_cfg = sources_cfg.get("crtsh", {})
    if crtsh_cfg.get("enabled", True):
        source_results["crtsh"] = await crtsh.fetch_from_crtsh(
            domain,
            timeout=float(crtsh_cfg.get("timeout", 30)),
            retries=int(crtsh_cfg.get("retries", 2)),
        )

    # --- extra passive OSINT sources (no API keys, graceful failures) ---
    if sources_cfg.get("hackertarget", {}).get("enabled", True):
        source_results["hackertarget"] = await passive_apis.fetch_from_hackertarget(
            domain, timeout=float(sources_cfg.get("hackertarget", {}).get("timeout", 25))
        )
    if sources_cfg.get("rapiddns", {}).get("enabled", True):
        source_results["rapiddns"] = await passive_apis.fetch_from_rapiddns(
            domain, timeout=float(sources_cfg.get("rapiddns", {}).get("timeout", 25))
        )

    # --- optional external binaries ---
    for tool, runner, default_timeout in _EXTERNAL_SOURCES:
        cfg = sources_cfg.get(tool, {})
        if not cfg.get("enabled", True):
            continue
        if find_tool(tool) is None:
            log.warning("%s is not installed — skipping (it is optional)", tool)
            continue
        timeout = float(cfg.get("timeout", default_timeout))
        # subprocess.run blocks; keep the event loop responsive via a thread.
        source_results[tool] = await asyncio.to_thread(runner, domain, timeout)

    # --- active wordlist brute-force ---
    if not skip_brute:
        bruteforce_cfg = settings.get("bruteforce", {})
        wl_path = (
            Path(wordlist)
            if wordlist is not None
            else PROJECT_ROOT / str(bruteforce_cfg.get("wordlist", "data/wordlists/subdomains.txt"))
        )
        source_results["bruteforce"] = await bruteforce.brute_force(
            domain,
            resolvers=[str(r) for r in general.get("resolvers", ["1.1.1.1", "8.8.8.8", "9.9.9.9"])],
            timeout=float(general.get("timeout", 10)),
            concurrency=int(general.get("concurrency", 100)),
            wordlist=wl_path,
            probe_count=int(bruteforce_cfg.get("wildcard_probe_count", 3)),
        )

    return merge_results(domain, source_results)
