"""Phase 3 pipeline: phase2_resolved.json → detectors → phase3_findings.json.

Detection is fully synchronous (a handful of live DNS re-checks only), so no
event loop is involved. The live resolver used for re-checks is built from the
configured resolver list — never the OS resolver config.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver

from src.detection.analyze import analyze
from src.detection.fingerprints import load_fingerprints
from src.discovery.validators import normalize_domain
from src.models import Phase2Result, Phase3Result
from src.utils.paths import read_json

log = logging.getLogger(__name__)

FALLBACK_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


class Phase3InputError(ValueError):
    """Raised when the Phase 2 input file is missing or not a valid contract."""


def build_sync_resolver(resolvers: list[str], timeout: float) -> dns.resolver.Resolver:
    """Sync resolver for the detection re-checks (configure=False → no OS config)."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [str(r) for r in resolvers]
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def load_phase2_file(path: Path) -> Phase2Result:
    """Read and validate a Phase 2 contract file; raises Phase3InputError."""
    path = Path(path)
    if not path.is_file():
        raise Phase3InputError(f"Input file not found: {path}")
    try:
        data = read_json(path)
    except (OSError, ValueError) as exc:  # ValueError covers JSONDecodeError
        raise Phase3InputError(f"Cannot parse {path} as JSON: {exc}") from exc
    if (
        not isinstance(data, dict)
        or not data.get("target")
        or not isinstance(data.get("records"), list)
    ):
        raise Phase3InputError(f"{path} is not a phase2_resolved.json contract file")
    result = Phase2Result.from_dict(data)
    try:
        result.target = normalize_domain(result.target)
    except ValueError as exc:
        raise Phase3InputError(
            f"Invalid target in input file: {result.target!r}"
        ) from exc
    valid = []
    for record in result.records:
        try:
            record.name = normalize_domain(record.name)
        except ValueError:
            log.warning("Skipping record with invalid name in input: %r", record.name)
            continue
        valid.append(record)
    result.records = valid
    return result


def run_detection(
    input_path: Path,
    settings: dict,
    fingerprints_path: Path | None = None,
    recheck_dns: bool | None = None,
) -> Phase3Result:
    """Run all detectors over the Phase 2 records and build Phase3Result."""
    phase2 = load_phase2_file(input_path)
    services, config = load_fingerprints(fingerprints_path)
    if recheck_dns is not None:
        config.recheck_dns = bool(recheck_dns)

    resolver = None
    if config.recheck_dns:
        general = settings.get("general", {})
        resolver = build_sync_resolver(
            [str(r) for r in general.get("resolvers", FALLBACK_RESOLVERS)],
            float(general.get("timeout", 10)),
        )

    result = analyze(phase2.target, phase2.records, services, config, resolver)
    result.generated_at = datetime.now(timezone.utc).isoformat()
    log.info(
        "Detection complete: %d finding(s) over %d record(s)",
        len(result.findings),
        len(phase2.records),
    )
    return result
