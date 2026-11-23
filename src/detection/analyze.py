"""Detector orchestration + confidence/severity scoring + summary."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from src.detection.detectors import (
    detect_dangling_a,
    detect_dangling_cname,
    detect_fingerprint,
    detect_ns_delegation,
)
from src.detection.fingerprints import DetectionConfig, ServiceFingerprint
from src.models import Phase3Result, ResolvedRecord

log = logging.getLogger(__name__)


def analyze(
    target: str,
    records: list[ResolvedRecord],
    services: list[ServiceFingerprint],
    config: DetectionConfig | None = None,
    resolver=None,
) -> Phase3Result:
    """Run every detector over all records; dedupe and score.

    Detector order doubles as priority: a record that triggers two detectors
    keeps the first finding (CNAME_FINGERPRINT evidence outranks the generic
    dangling signal for the same record).
    """
    config = config or DetectionConfig()
    recheck_resolver = resolver if config.recheck_dns else None
    findings: list = []
    seen: set[tuple[str, str]] = set()

    for record in records:
        for candidate in (
            detect_fingerprint(record, services),
            detect_dangling_cname(record, services, recheck_resolver),
            detect_ns_delegation(record, resolver),
            detect_dangling_a(record, services, config),
        ):
            for finding in candidate:
                key = (finding.subdomain, finding.type)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

    by_confidence = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        by_confidence[finding.confidence] = by_confidence.get(finding.confidence, 0) + 1

    summary = {
        "total_scanned": len(records),
        "vulnerable": by_confidence.get("HIGH", 0),
        "by_confidence": by_confidence,
    }
    log.info(
        "Analyzed %d records: %d finding(s) (HIGH=%d MEDIUM=%d LOW=%d)",
        len(records),
        len(findings),
        by_confidence["HIGH"],
        by_confidence["MEDIUM"],
        by_confidence["LOW"],
    )
    return Phase3Result(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        summary=summary,
    )
