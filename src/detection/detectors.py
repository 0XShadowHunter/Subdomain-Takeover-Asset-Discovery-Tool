"""The four takeover detectors (AGENT_PLAN.md §5).

Safety (§1 rule 5, mandatory): every function here only *detects and reports*.
Nothing claims, registers, exploits, or modifies any resource — remediation is
advice text only.

False-positive reduction rules implemented:
- services marked ``not-vulnerable`` are skipped entirely;
- a generic 404/410 without a matching fingerprint is ignored (no finding);
- dangling-CNAME candidates are re-checked with a second live DNS query
  before flagging (inconclusive re-checks are treated as alive — conservative);
- detector 4 is disabled by default (best-effort only).
"""

from __future__ import annotations

import logging

import dns.exception
import dns.resolver

from src.detection.fingerprints import DetectionConfig, ServiceFingerprint
from src.discovery.dns_client import DnsStatus
from src.models import Finding, ResolvedRecord

log = logging.getLogger(__name__)


def _http_text(record: ResolvedRecord) -> str:
    """Title + body snippet joined for fingerprint matching."""
    return " ".join(
        part for part in (record.http.title or "", record.http.body_snippet or "") if part
    )


def detect_fingerprint(record: ResolvedRecord, services: list[ServiceFingerprint]) -> list[Finding]:
    """Detector 1: CNAME points at a known service whose 404 page matches."""
    findings: list[Finding] = []
    if len(record.cname_chain) < 2:
        return findings
    target = record.cname_chain[-1]
    text = _http_text(record)
    for svc in services:
        if svc.status == "not-vulnerable" or not svc.matches_cname(target):
            continue
        matched = svc.match_fingerprint(text)
        if not matched:
            continue  # includes generic 404s — ignored per the FP rules
        confidence = "HIGH" if svc.status == "vulnerable" else "MEDIUM"
        findings.append(
            Finding(
                subdomain=record.name,
                type="CNAME_FINGERPRINT",
                service=svc.service,
                cname_target=target,
                evidence=(
                    f"CNAME → {target}; HTTP {record.http.status or '?'} matched "
                    f"fingerprint {matched!r} (service status: {svc.status})"
                ),
                confidence=confidence,
                severity=svc.severity,
                references=list(svc.references),
                remediation=svc.remediation
                or "Remove the dangling CNAME record or reclaim the service resource.",
            )
        )
    return findings


def _still_resolves(resolver, name: str) -> bool:
    """True when ``name`` resolves (A or CNAME); inconclusive errors count as alive."""
    try:
        resolver.resolve(name, "A")
        return True
    except dns.resolver.NXDOMAIN:
        pass
    except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers, OSError):
        return True  # inconclusive → conservative: treat as alive
    try:
        resolver.resolve(name, "CNAME")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers, OSError):
        return True
    return False


def detect_dangling_cname(
    record: ResolvedRecord,
    services: list[ServiceFingerprint],
    resolver=None,
) -> list[Finding]:
    """Detector 2: CNAME chain whose target no longer resolves (NXDOMAIN).

    The Phase 2 signal is ``resolved=True`` + ``dns_status=NXDOMAIN`` + a chain
    longer than the name itself. Confidence: MEDIUM by default, HIGH when the
    target matches a service marked ``nxdomain: true`` (the target itself can
    be registered).
    """
    if not (
        record.resolved
        and record.dns_status == DnsStatus.NXDOMAIN
        and len(record.cname_chain) > 1
    ):
        return []
    target = record.cname_chain[-1]
    verified = "captured during the resolve phase"
    if resolver is not None:
        if _still_resolves(resolver, target):
            log.info(
                "Dangling-CNAME candidate %s resolved on re-check — skipped", target
            )
            return []
        verified = "confirmed by a second DNS query (NXDOMAIN)"

    matched_service: ServiceFingerprint | None = None
    confidence = "MEDIUM"
    for svc in services:
        if svc.matches_cname(target):
            matched_service = svc
            if svc.nxdomain:
                confidence = "HIGH"
            break

    return [
        Finding(
            subdomain=record.name,
            type="CNAME_NXDOMAIN",
            service=matched_service.service if matched_service else "unknown",
            cname_target=target,
            evidence=(
                f"CNAME → {target} does not resolve ({verified}); "
                "the target name may be registrable or its service resource was deleted"
            ),
            confidence=confidence,
            severity="HIGH",
            references=(
                list(matched_service.references)
                if matched_service
                else ["https://github.com/EdOverflow/can-i-take-over-xyz"]
            ),
            remediation=(
                matched_service.remediation
                if matched_service
                else "Remove the dangling CNAME record, or reclaim the target "
                "(register the domain / recreate the service resource)."
            ),
        )
    ]


def detect_ns_delegation(record: ResolvedRecord, resolver=None) -> list[Finding]:
    """Detector 3: NS delegation whose nameservers are all unresolvable.

    Requires a live resolver (the NS names' resolvability is not in the
    Phase 2 contract). All-dead delegation → MEDIUM/HIGH finding; any live NS
    → delegation is fine.
    """
    if not record.ns or resolver is None:
        return []
    dead = [ns_name for ns_name in record.ns if not _still_resolves(resolver, ns_name)]
    if len(dead) < len(record.ns):
        return []  # at least one nameserver answers — delegation is alive
    return [
        Finding(
            subdomain=record.name,
            type="NS_DELEGATION",
            service="unknown",
            cname_target=None,
            evidence=(
                f"Zone delegated to {', '.join(record.ns)} but none of the "
                f"nameservers resolve ({', '.join(dead)})"
            ),
            confidence="MEDIUM",
            severity="HIGH",
            references=[
                "https://github.com/EdOverflow/can-i-take-over-xyz",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-web_application_security_testing/configuration_and_deployment_management_testing/10-testing_for_subdomain_takeover",
            ],
            remediation=(
                "Remove the stale delegation/NS records, or re-create the missing "
                "nameservers under a name you control."
            ),
        )
    ]


def detect_dangling_a(
    record: ResolvedRecord,
    services: list[ServiceFingerprint],
    config: DetectionConfig,
) -> list[Finding]:
    """Detector 4 (optional/best-effort): A-only records whose page matches a
    configured fingerprint. Disabled unless ``detection.enable_dangling_a`` is
    true AND fingerprint entries without cname_patterns exist (they double as
    A-page fingerprints). Always reported at LOW confidence."""
    if not config.enable_dangling_a:
        return []
    if len(record.cname_chain) > 1 or not (record.a or record.aaaa):
        return []  # CNAME cases belong to detectors 1/2; no address → skip
    text = _http_text(record)
    for svc in services:
        if svc.status != "vulnerable" or svc.cname_patterns:
            continue  # pattern-less entries are the A-page fingerprints
        matched = svc.match_fingerprint(text)
        if matched:
            return [
                Finding(
                    subdomain=record.name,
                    type="DANGLING_A",
                    service=svc.service,
                    cname_target=None,
                    evidence=(
                        f"A record {record.a[0]} serves HTTP {record.http.status or '?'} "
                        f"matching fingerprint {matched!r} — manual review required"
                    ),
                    confidence="LOW",
                    severity="MEDIUM",
                    references=list(svc.references),
                    remediation=svc.remediation
                    or "Verify the host manually; remove or reclaim the address if unowned.",
                )
            ]
    return []
