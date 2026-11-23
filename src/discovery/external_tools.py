"""Optional wrappers for external enumeration binaries.

Covers subfinder, amass, and assetfinder (AGENT_PLAN.md §3). Contract rules
(§1.1 #3): locate via ``find_tool()`` (``shutil.which``); if a tool is missing,
skip it with a warning — the run must stay fully functional with Python only;
subprocesses use list args and a timeout, never ``shell=True``.
"""

from __future__ import annotations

import logging
import subprocess

from src.utils.platform import find_tool, run_subprocess

log = logging.getLogger(__name__)


def filter_lines_to_domain(text: str, domain: str) -> list[str]:
    """Keep only names equal to/under the target, normalized and deduped."""
    suffix = "." + domain
    names: set[str] = set()
    for line in (text or "").splitlines():
        name = line.strip().lower().lstrip("*. ").rstrip(".")
        if name == domain or name.endswith(suffix):
            names.add(name)
    return sorted(names)


def _run_enum_tool(
    tool: str, args: list[str], domain: str, timeout: float
) -> list[str]:
    """Run one enumeration binary; return [] when missing or failing."""
    path = find_tool(tool)
    if not path:
        log.warning(
            "%s not found on PATH — skipping (optional; pure-Python sources still run)",
            tool,
        )
        return []
    try:
        proc = run_subprocess([path, *args], timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("%s failed for %s: %s", tool, domain, exc)
        return []
    names = filter_lines_to_domain(proc.stdout.decode("utf-8", "replace"), domain)
    log.info("%s: %d names for %s", tool, len(names), domain)
    return names


def run_subfinder(domain: str, timeout: float = 60.0) -> list[str]:
    """Passive enumeration via subfinder (-silent prints names only)."""
    return _run_enum_tool("subfinder", ["-d", domain, "-silent"], domain, timeout)


def run_assetfinder(domain: str, timeout: float = 60.0) -> list[str]:
    """Fast passive enumeration via assetfinder (--subs-only filters subdomains)."""
    return _run_enum_tool("assetfinder", ["--subs-only", domain], domain, timeout)


def run_amass(domain: str, timeout: float = 120.0) -> list[str]:
    """OWASP amass in passive mode (can be slow; timeout guards the run)."""
    return _run_enum_tool("amass", ["enum", "-passive", "-d", domain], domain, timeout)
