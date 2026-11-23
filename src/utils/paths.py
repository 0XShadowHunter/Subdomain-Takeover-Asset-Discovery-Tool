"""Pathlib helpers: single source of truth for all file locations.

Every module must resolve files through this module (never hard-coded paths)
so the tool behaves identically on Windows and Linux (AGENT_PLAN.md §1.1 #1).
Also hosts the built-in settings defaults used when config/settings.yaml is
absent or incomplete.

Frozen mode (PyInstaller exe): read-only resources (config, wordlists, Jinja2
templates) ship inside the bundle (_MEIPASS), while generated outputs land
next to the executable so they survive after the temp dir is gone.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

#: True when running as a PyInstaller-built executable.
FROZEN = bool(getattr(sys, "frozen", False))

def _find_project_root(start: Path) -> Path | None:
    """Walk up from ``start`` looking for the project marker.

    The marker is ``config/settings.yaml`` — every checkout of this project
    has one. Used by the frozen exe to save results into the real project's
    data folder instead of beside itself.
    """
    for candidate in (start, *start.parents):
        if (candidate / "config" / "settings.yaml").is_file():
            return candidate
    return None


if FROZEN:
    # Read-only resources bundled by PyInstaller.
    RESOURCE_ROOT: Path = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    # Writable outputs: the exe lives in <project>/dist/, so walk up to the
    # project checkout and save into ITS data folder; when no project marker
    # is found (exe copied elsewhere), fall back to beside-the-exe storage.
    exe_dir = Path(sys.executable).resolve().parent
    detected = _find_project_root(exe_dir)
    PROJECT_ROOT: Path = detected if detected is not None else exe_dir
else:
    # Project root = three levels up from this file (src/utils/paths.py).
    RESOURCE_ROOT: Path = Path(__file__).resolve().parents[2]
    PROJECT_ROOT: Path = RESOURCE_ROOT

CONFIG_DIR: Path = RESOURCE_ROOT / "config"
DATA_DIR: Path = PROJECT_ROOT / "data"
WORDLIST_DIR: Path = RESOURCE_ROOT / "data" / "wordlists"
OUTPUT_DIR: Path = DATA_DIR / "output"
#: Main folder holding ALL saved scan data (SQLite + artifacts), with one
#: sub-area per origin: results/cli/<domain>/ and results/gui/<domain>/.
RESULTS_DIR: Path = DATA_DIR / "results"

SETTINGS_FILE: Path = CONFIG_DIR / "settings.yaml"
DEFAULT_FINGERPRINTS: Path = CONFIG_DIR / "fingerprints.yaml"
#: Branding assets shown in the GUI (and bundled into the frozen exe):
#: the wide word-mark for the header + the square render for window icons.
LOGO_FILE: Path = RESOURCE_ROOT / "assets" / "logo.png"
ICON_FILE: Path = RESOURCE_ROOT / "assets" / "icon_256.png"

PHASE1_OUTPUT: Path = OUTPUT_DIR / "phase1_subdomains.json"
PHASE2_OUTPUT: Path = OUTPUT_DIR / "phase2_resolved.json"
PHASE3_OUTPUT: Path = OUTPUT_DIR / "phase3_findings.json"

DEFAULT_WORDLIST: Path = WORDLIST_DIR / "subdomains.txt"

#: Public resolvers used everywhere DNS is queried. Kept here so the settings
#: defaults and the DNS layer share one source of truth (AGENT_PLAN.md §1.1 #4).
DEFAULT_RESOLVERS: list[str] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

#: Fallback settings when config/settings.yaml is missing or partial.
DEFAULT_SETTINGS: dict[str, Any] = {
    "general": {
        "timeout": 10,
        "concurrency": 100,
        "resolvers": DEFAULT_RESOLVERS,
    },
    "bruteforce": {
        "wordlist": "data/wordlists/subdomains.txt",
        "wildcard_probe_count": 3,
    },
    "sources": {
        "crtsh": {"enabled": True, "timeout": 30, "retries": 2},
        "hackertarget": {"enabled": True, "timeout": 25},
        "rapiddns": {"enabled": True, "timeout": 25},
        "subfinder": {"enabled": True, "timeout": 60},
        "amass": {"enabled": True, "timeout": 120},
        "assetfinder": {"enabled": True, "timeout": 60},
    },
    "api_keys": {
        "shodan": "",
        "virustotal": "",
    },
}


def domain_output_dir(domain: str, source: str = "cli") -> Path:
    """Dedicated results folder for one domain, separated by origin.

    Layout: ``data/results/<source>/<domain>/`` where ``source`` is ``cli`` or
    ``gui`` — so command-line scans and GUI scans never mix, under one main
    results folder. Keeps every artifact of a target (phase JSONs, SQLite
    history, reports) in one place. The domain must already be normalized;
    characters outside [a-z0-9.-] are replaced to stay filesystem-safe on
    Windows and Linux.
    """
    safe = "".join(ch if (ch.isalnum() or ch in ".-") else "-" for ch in domain.lower())
    area = (source or "cli").strip().lower()
    if area not in ("cli", "gui"):
        area = "cli"
    return RESULTS_DIR / area / safe


def ensure_dirs() -> None:
    """Create the data sub-folders if missing (idempotent)."""
    for directory in (DATA_DIR, WORDLIST_DIR, OUTPUT_DIR, RESULTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def load_settings(path: Path | None = None) -> dict[str, Any]:
    """Load config/settings.yaml and merge it over the built-in defaults.

    Missing sections/keys silently keep their defaults, so a trimmed settings
    file never crashes a run. Returns a fresh dict on every call.
    """
    settings_path = path if path is not None else SETTINGS_FILE
    merged: dict[str, Any] = {
        section: (dict(values) if isinstance(values, dict) else values)
        for section, values in DEFAULT_SETTINGS.items()
    }
    if not settings_path.is_file():
        log.warning("Settings file not found at %s — using defaults", settings_path)
        return merged
    try:
        import yaml  # imported lazily: settings loading must not hard-require PyYAML

        loaded = yaml.safe_load(settings_path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — bad YAML must never kill a scan
        log.exception("Failed to parse %s — using defaults", settings_path)
        return merged
    if not isinstance(loaded, dict):
        log.warning("%s does not contain a mapping — using defaults", settings_path)
        return merged
    for section, values in loaded.items():
        if isinstance(values, dict) and isinstance(merged.get(section), dict):
            merged[section].update(values)
        else:
            merged[section] = values
    return merged


def dump_json(data: Any, path: Path) -> Path:
    """Write JSON as UTF-8 (portable), creating parent folders as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def read_json(path: Path) -> Any:
    """Read JSON written by dump_json (UTF-8)."""
    return json.loads(path.read_text(encoding="utf-8"))
