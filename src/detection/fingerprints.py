"""Fingerprint loading and matching (config/fingerprints.yaml).

Fingerprints come from the can-i-take-over-xyz reference and are fully
editable in YAML — adding or updating services requires NO code changes
(AGENT_PLAN.md §5 acceptance criteria). Invalid entries are skipped with a
warning so a hand-edited file can never crash a scan.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.models import SEVERITY_LEVELS
from src.utils.paths import DEFAULT_FINGERPRINTS

log = logging.getLogger(__name__)

VALID_STATUSES = ("vulnerable", "edge-case", "not-vulnerable")


@dataclass
class ServiceFingerprint:
    """One service entry from config/fingerprints.yaml."""

    service: str
    cname_patterns: list[str] = field(default_factory=list)
    fingerprints: list[str] = field(default_factory=list)
    nxdomain: bool = False
    status: str = "not-vulnerable"
    severity: str = "INFO"
    references: list[str] = field(default_factory=list)
    remediation: str = ""

    @classmethod
    def from_dict(cls, data: Any, index: int = 0) -> ServiceFingerprint:
        if not isinstance(data, dict):
            raise ValueError(f"entry #{index} is not a mapping")
        service = str(data.get("service") or "").strip()
        if not service:
            raise ValueError(f"entry #{index} has no service name")
        status = str(data.get("status") or "not-vulnerable").strip().lower()
        if status not in VALID_STATUSES:
            raise ValueError(
                f"entry #{index} ({service}): unknown status {status!r} "
                f"(expected one of {VALID_STATUSES})"
            )
        severity = str(data.get("severity") or "INFO").strip().upper()
        if severity not in SEVERITY_LEVELS:
            log.warning(
                "fingerprints entry %s: unknown severity %r — using MEDIUM", service, severity
            )
            severity = "MEDIUM"
        return cls(
            service=service,
            cname_patterns=[str(p) for p in (data.get("cname_patterns") or [])],
            fingerprints=[str(f) for f in (data.get("fingerprints") or [])],
            nxdomain=bool(data.get("nxdomain", False)),
            status=status,
            severity=severity,
            references=[str(r) for r in (data.get("references") or [])],
            remediation=str(data.get("remediation") or ""),
        )

    def matches_cname(self, target: str) -> bool:
        """True when the CNAME target matches any pattern (fnmatch, case-insensitive)."""
        target = (target or "").lower()
        return any(fnmatch.fnmatch(target, pattern.lower()) for pattern in self.cname_patterns)

    def match_fingerprint(self, text: str) -> str | None:
        """Return the first fingerprint substring found in ``text``, else None."""
        if not text:
            return None
        low = text.lower()
        for fingerprint in self.fingerprints:
            if fingerprint.lower() in low:
                return fingerprint
        return None


@dataclass
class DetectionConfig:
    """Knobs from the ``detection:`` section of fingerprints.yaml."""

    recheck_dns: bool = True
    enable_dangling_a: bool = False


def load_fingerprints(
    path: Path | str | None = None,
) -> tuple[list[ServiceFingerprint], DetectionConfig]:
    """Load services + detection config; skip invalid entries with warnings."""
    fingerprints_path = Path(path) if path is not None else DEFAULT_FINGERPRINTS
    if not fingerprints_path.is_file():
        log.warning(
            "Fingerprints file not found: %s — detection runs with no services",
            fingerprints_path,
        )
        return [], DetectionConfig()
    try:
        import yaml  # lazily: module import must not hard-require PyYAML

        data = yaml.safe_load(fingerprints_path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — bad YAML must never kill a scan
        log.exception("Failed to parse %s — detection runs with no services", fingerprints_path)
        return [], DetectionConfig()
    if not isinstance(data, dict):
        log.warning("%s does not contain a mapping — using defaults", fingerprints_path)
        return [], DetectionConfig()

    services: list[ServiceFingerprint] = []
    for index, entry in enumerate(data.get("services") or []):
        try:
            services.append(ServiceFingerprint.from_dict(entry, index))
        except (ValueError, TypeError) as exc:
            log.warning("Skipping invalid fingerprints entry: %s", exc)
    detection_cfg = data.get("detection") or {}
    config = DetectionConfig(
        recheck_dns=bool(detection_cfg.get("recheck_dns", True)),
        enable_dangling_a=bool(detection_cfg.get("enable_dangling_a", False)),
    )
    log.info("Loaded %d service fingerprint(s) from %s", len(services), fingerprints_path)
    return services, config
