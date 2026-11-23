"""OS detection, external-tool location, and event-loop/subprocess helpers.

Cross-platform rules from AGENT_PLAN.md §1.1:
- Locate binaries with ``shutil.which`` — never hard-code paths; ``.exe`` is
  handled automatically on Windows.
- asyncio only; no uvloop, aiodns, or Linux-only modules.
- Subprocesses: list args, never ``shell=True``, always a timeout.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import sys

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"

#: Known binary aliases per tool. On Kali, ProjectDiscovery's httpx is often
#: packaged as ``httpx-toolkit`` to avoid clashing with the Python httpx CLI,
#: so both names are tried (AGENT_PLAN.md §1.1 #3).
TOOL_ALIASES: dict[str, list[str]] = {
    "subfinder": ["subfinder"],
    "amass": ["amass"],
    "assetfinder": ["assetfinder"],
    "findomain": ["findomain"],
    "httpx": ["httpx-toolkit", "httpx"],
    "dnsx": ["dnsx"],
    "nuclei": ["nuclei"],
    "subjack": ["subjack"],
    "subzy": ["subzy"],
}


def find_tool(name: str) -> str | None:
    """Return the absolute path of an external tool, or None if not installed.

    ``name`` is the canonical tool name (e.g. ``"httpx"``); all known aliases
    are tried in order, so ``httpx-toolkit`` on Kali is found transparently.
    """
    for alias in TOOL_ALIASES.get(name, [name]):
        path = shutil.which(alias)
        if path:
            log.debug("Found %s as %s", name, path)
            return path
    return None


def setup_event_loop_policy() -> None:
    """Make asyncio behave consistently across operating systems.

    On Windows, the default Proactor loop is not supported by every library;
    switching to the selector policy keeps behavior aligned with Linux. On
    POSIX nothing needs to change (uvloop is deliberately never used).
    """
    if IS_WINDOWS:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def run_async(coro):
    """Run a coroutine to completion with the cross-platform loop policy."""
    setup_event_loop_policy()
    return asyncio.run(coro)


def attach_parent_console() -> None:
    """Reattach output to the parent terminal for windowed (PyInstaller) exes.

    A ``--windowed`` build has no console of its own, so double-clicking the
    exe opens the GUI silently. When the very same exe is launched *from a
    terminal*, this reattaches to the parent console so CLI output stays
    visible. No-op on non-Windows and unfrozen runs.
    """
    if not (IS_WINDOWS and getattr(sys, "frozen", False)):
        return
    try:
        if sys.stdout is not None and sys.stdout.isatty():
            return  # already attached to a console
        import ctypes

        kernel32 = ctypes.windll.kernel32
        if kernel32.AttachConsole(-1):  # ATTACH_PARENT_PROCESS
            sys.stdout = open(  # noqa: SIM115 — console handle, managed by the OS
                "CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1
            )
            sys.stderr = open(  # noqa: SIM115
                "CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1
            )
            try:
                sys.stdin = open("CONIN$", encoding="utf-8", errors="replace")  # noqa: SIM115
            except OSError:
                pass
    except Exception:  # noqa: BLE001 — cosmetic: worst case output stays hidden
        pass


def run_subprocess(cmd: list[str], timeout: float) -> subprocess.CompletedProcess:
    """Run an external tool safely: list args (no shell), capped by timeout.

    ``subprocess.TimeoutExpired`` is normalized to the built-in ``TimeoutError``
    so callers can catch a single exception type on every OS.
    """
    log.debug("Running: %s", " ".join(cmd))
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            check=False,
            shell=False,  # explicit: never route through a shell (§1.1 #3)
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"Command timed out after {timeout}s: {cmd[0]}") from exc
