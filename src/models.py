"""Shared data models — the Data Contracts from AGENT_PLAN.md §2.

Every phase reads/writes these JSON shapes under data/output/. Any change to a
contract must be made here AND in AGENT_PLAN.md §2 (see the handoff protocol
in §1 of the plan).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Phase 1 — subdomain enumeration (data/output/phase1_subdomains.json)
# ---------------------------------------------------------------------------


@dataclass
class SubdomainEntry:
    """One discovered subdomain plus every source that reported it."""

    name: str
    sources: list[str] = field(default_factory=list)

    def add_source(self, source: str) -> None:
        if source and source not in self.sources:
            self.sources.append(source)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "sources": list(self.sources)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubdomainEntry:
        return cls(
            name=str(data.get("name", "")),
            sources=[str(s) for s in data.get("sources", [])],
        )


@dataclass
class Phase1Result:
    """Contract file: data/output/phase1_subdomains.json"""

    target: str
    generated_at: str
    sources_used: list[str] = field(default_factory=list)
    subdomains: list[SubdomainEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "sources_used": list(self.sources_used),
            "subdomains": [entry.to_dict() for entry in self.subdomains],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Phase1Result:
        return cls(
            target=str(data.get("target", "")),
            generated_at=str(data.get("generated_at", "")),
            sources_used=[str(s) for s in data.get("sources_used", [])],
            subdomains=[
                SubdomainEntry.from_dict(entry) for entry in data.get("subdomains", [])
            ],
        )


# ---------------------------------------------------------------------------
# Phase 2 — DNS resolution & HTTP probing (data/output/phase2_resolved.json)
# ---------------------------------------------------------------------------

DNS_STATUSES = ("NOERROR", "NXDOMAIN", "SERVFAIL", "TIMEOUT", "NODATA")


@dataclass
class HttpInfo:
    """HTTP probe result for one subdomain (Phase 2)."""

    url: str | None = None
    status: int | None = None
    title: str | None = None
    body_snippet: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    redirects: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "title": self.title,
            "body_snippet": self.body_snippet,
            "headers": dict(self.headers),
            "redirects": list(self.redirects),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HttpInfo:
        return cls(
            url=data.get("url"),
            status=data.get("status"),
            title=data.get("title"),
            body_snippet=data.get("body_snippet"),
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
            redirects=[str(r) for r in data.get("redirects", [])],
            error=data.get("error"),
        )


@dataclass
class ResolvedRecord:
    """DNS + HTTP facts for one subdomain (Phase 2)."""

    name: str
    resolved: bool = False
    dns_status: str = "NXDOMAIN"
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    http: HttpInfo = field(default_factory=HttpInfo)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "resolved": self.resolved,
            "dns_status": self.dns_status,
            "a": list(self.a),
            "aaaa": list(self.aaaa),
            "cname_chain": list(self.cname_chain),
            "ns": list(self.ns),
            "http": self.http.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResolvedRecord:
        return cls(
            name=str(data.get("name", "")),
            resolved=bool(data.get("resolved", False)),
            dns_status=str(data.get("dns_status", "NXDOMAIN")),
            a=[str(x) for x in data.get("a", [])],
            aaaa=[str(x) for x in data.get("aaaa", [])],
            cname_chain=[str(x) for x in data.get("cname_chain", [])],
            ns=[str(x) for x in data.get("ns", [])],
            http=HttpInfo.from_dict(data.get("http") or {}),
        )


@dataclass
class Phase2Result:
    """Contract file: data/output/phase2_resolved.json"""

    target: str
    generated_at: str
    records: list[ResolvedRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "records": [record.to_dict() for record in self.records],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Phase2Result:
        return cls(
            target=str(data.get("target", "")),
            generated_at=str(data.get("generated_at", "")),
            records=[
                ResolvedRecord.from_dict(record) for record in data.get("records", [])
            ],
        )


# ---------------------------------------------------------------------------
# Phase 3 — takeover detection (data/output/phase3_findings.json)
# ---------------------------------------------------------------------------

FINDING_TYPES = ("CNAME_FINGERPRINT", "CNAME_NXDOMAIN", "NS_DELEGATION", "DANGLING_A")
CONFIDENCE_LEVELS = ("HIGH", "MEDIUM", "LOW")
SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass
class Finding:
    """One takeover finding with evidence, confidence, and remediation."""

    subdomain: str
    type: str
    service: str = ""
    cname_target: str | None = None
    evidence: str = ""
    confidence: str = "LOW"
    severity: str = "INFO"
    references: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "subdomain": self.subdomain,
            "type": self.type,
            "service": self.service,
            "cname_target": self.cname_target,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "severity": self.severity,
            "references": list(self.references),
            "remediation": self.remediation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            subdomain=str(data.get("subdomain", "")),
            type=str(data.get("type", "")),
            service=str(data.get("service", "")),
            cname_target=data.get("cname_target"),
            evidence=str(data.get("evidence", "")),
            confidence=str(data.get("confidence", "LOW")),
            severity=str(data.get("severity", "INFO")),
            references=[str(r) for r in data.get("references", [])],
            remediation=str(data.get("remediation", "")),
        )


@dataclass
class Phase3Result:
    """Contract file: data/output/phase3_findings.json"""

    target: str
    generated_at: str
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": dict(self.summary),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Phase3Result:
        return cls(
            target=str(data.get("target", "")),
            generated_at=str(data.get("generated_at", "")),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            summary=dict(data.get("summary") or {}),
        )
