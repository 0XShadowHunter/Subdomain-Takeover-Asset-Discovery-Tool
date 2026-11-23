"""Detector tests — fixtures for the required services + FP-reduction rules.

All live DNS is mocked with a fake sync resolver; fingerprint fixtures use the
shipped config/fingerprints.yaml (no network anywhere).
"""

import dns.exception
import dns.resolver

from src.detection.detectors import (
    detect_dangling_a,
    detect_dangling_cname,
    detect_fingerprint,
    detect_ns_delegation,
)
from src.detection.fingerprints import DetectionConfig, ServiceFingerprint, load_fingerprints
from src.discovery.dns_client import DnsStatus
from src.models import HttpInfo, ResolvedRecord

SERVICES, CONFIG = load_fingerprints()
BY_NAME = {svc.service: svc for svc in SERVICES}


class FakeAddr:
    def __init__(self, address):
        self.address = address


class FakeSyncResolver:
    """(name, rdtype) -> values | Exception.

    Missing keys raise NXDOMAIN — mirroring a query against a nonexistent
    name (the common case for dangling-candidate re-checks).
    """

    def __init__(self, table=None):
        self.table = dict(table or {})

    def resolve(self, name, rdtype):
        value = self.table.get((name, rdtype))
        if value is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(value, Exception):
            raise value
        return value


def _record(name, target=None, status=200, title=None, body=None, **kwargs):
    chain = [name] + ([target] if target else [])
    http = HttpInfo(status=status, title=title, body_snippet=body)
    return ResolvedRecord(name=name, cname_chain=chain, http=http, **kwargs)


# ------------------------- Detector 1: fingerprints -------------------------


def test_github_pages_fingerprint_match():
    record = _record(
        "blog.example.com",
        target="blog.example.github.io",
        status=404,
        body="There isn't a GitHub Pages site here.",
    )
    findings = detect_fingerprint(record, SERVICES)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "CNAME_FINGERPRINT"
    assert finding.service == "GitHub Pages"
    assert finding.confidence == "HIGH"
    assert finding.severity == "HIGH"
    assert finding.cname_target == "blog.example.github.io"
    assert finding.remediation
    assert finding.references


def test_s3_fingerprint_match():
    s3_body = (
        "<Error><Code>NoSuchBucket</Code>"
        "<Message>The specified bucket does not exist</Message></Error>"
    )
    record = _record(
        "assets.example.com",
        target="example-assets.s3.amazonaws.com",
        status=404,
        body=s3_body,
    )
    findings = detect_fingerprint(record, SERVICES)
    assert len(findings) == 1
    assert findings[0].service == "AWS S3"
    assert findings[0].confidence == "HIGH"


def test_heroku_fingerprint_match():
    record = _record(
        "app.example.com", target="ancient-app.herokuapp.com", status=404, body="No such app"
    )
    findings = detect_fingerprint(record, SERVICES)
    assert len(findings) == 1
    assert findings[0].service == "Heroku"


def test_azure_fingerprint_match():
    record = _record(
        "site.example.com",
        target="old-site.azurewebsites.net",
        status=404,
        body="404 Web Site not found.",
    )
    findings = detect_fingerprint(record, SERVICES)
    assert len(findings) == 1
    assert findings[0].service == "Azure Web Apps"


def test_netlify_fingerprint_match():
    record = _record(
        "marketing.example.com", target="old-campaign.netlify.app", status=404, body="Not found"
    )
    findings = detect_fingerprint(record, SERVICES)
    assert len(findings) == 1
    assert findings[0].service == "Netlify"
    assert findings[0].confidence == "HIGH"


def test_edge_case_service_reports_medium():
    record = _record(
        "status.example.com",
        target="status.pingdom.com",
        status=404,
        body="sorry, couldn't find the status page",
    )
    findings = detect_fingerprint(record, SERVICES)
    assert len(findings) == 1
    assert findings[0].confidence == "MEDIUM"
    assert findings[0].severity == "LOW"


def test_not_vulnerable_service_never_flagged():
    record = _record(
        "cdn.example.com",
        target="d123abc4.cloudfront.net",
        status=403,
        body="ERROR: The request could not be satisfied",
    )
    assert detect_fingerprint(record, SERVICES) == []


def test_generic_404_without_fingerprint_ignored():
    record = _record(
        "app.example.com",
        target="ancient-app.herokuapp.com",
        status=404,
        body="custom totally-unrelated 404 page",
    )
    assert detect_fingerprint(record, SERVICES) == []


def test_200_ok_content_not_flagged():
    record = _record(
        "shop.example.com",
        target="store.myshopify.com",
        status=200,
        body="Welcome to our real store!",
    )
    assert detect_fingerprint(record, SERVICES) == []


def test_no_cname_no_fingerprint_check():
    record = _record("www.example.com", status=404, body="There isn't a GitHub Pages site here.")
    assert detect_fingerprint(record, SERVICES) == []


# ------------------------ Detector 2: dangling CNAME ------------------------


def test_dangling_cname_confirmed_by_recheck():
    record = ResolvedRecord(
        name="lost.example.com",
        resolved=True,
        dns_status=DnsStatus.NXDOMAIN,
        cname_chain=["lost.example.com", "deleted.example.github.io"],
    )
    resolver = FakeSyncResolver()  # every query NXDOMAIN
    findings = detect_dangling_cname(record, SERVICES, resolver)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "CNAME_NXDOMAIN"
    assert finding.confidence == "MEDIUM"  # default (no nxdomain:true service matched)
    assert finding.severity == "HIGH"
    assert "second DNS query" in finding.evidence


def test_dangling_cname_high_when_target_claimable():
    record = ResolvedRecord(
        name="lost.example.com",
        resolved=True,
        dns_status=DnsStatus.NXDOMAIN,
        cname_chain=["lost.example.com", "app.testclaim.example"],
    )
    claimable = ServiceFingerprint(
        service="Test Cloud",
        cname_patterns=["*.testclaim.example"],
        fingerprints=[],
        nxdomain=True,  # the target itself is registrable
        status="vulnerable",
        severity="HIGH",
    )
    resolver = FakeSyncResolver()
    findings = detect_dangling_cname(record, [claimable], resolver)
    assert len(findings) == 1
    assert findings[0].confidence == "HIGH"
    assert findings[0].service == "Test Cloud"


def test_dangling_cname_recheck_resolves_skipped():
    record = ResolvedRecord(
        name="lost.example.com",
        resolved=True,
        dns_status=DnsStatus.NXDOMAIN,
        cname_chain=["lost.example.com", "deleted.example.github.io"],
    )
    resolver = FakeSyncResolver(
        {("deleted.example.github.io", "A"): [FakeAddr("93.184.216.34")]}
    )
    assert detect_dangling_cname(record, SERVICES, resolver) == []


def test_dangling_cname_inconclusive_recheck_skipped():
    # Conservative rule: a timeout/SERVFAIL re-check must NOT produce a finding.
    record = ResolvedRecord(
        name="lost.example.com",
        resolved=True,
        dns_status=DnsStatus.NXDOMAIN,
        cname_chain=["lost.example.com", "deleted.example.github.io"],
    )
    resolver = FakeSyncResolver(
        {("deleted.example.github.io", "A"): dns.exception.Timeout()}
    )
    assert detect_dangling_cname(record, SERVICES, resolver) == []


def test_dangling_cname_without_resolver_still_flags():
    record = ResolvedRecord(
        name="lost.example.com",
        resolved=True,
        dns_status=DnsStatus.NXDOMAIN,
        cname_chain=["lost.example.com", "deleted.example.github.io"],
    )
    findings = detect_dangling_cname(record, SERVICES, None)
    assert len(findings) == 1
    assert "captured during the resolve phase" in findings[0].evidence


def test_dangling_cname_target_matches_no_service():
    # Regression: a dangling target outside every fingerprint pattern must
    # still produce a finding with the default reference (matched_service=None).
    record = ResolvedRecord(
        name="lost.example.com",
        resolved=True,
        dns_status=DnsStatus.NXDOMAIN,
        cname_chain=["lost.example.com", "this-does-not-exist-demo-2026.invalid"],
    )
    resolver = FakeSyncResolver()
    findings = detect_dangling_cname(record, SERVICES, resolver)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.service == "unknown"
    assert finding.confidence == "MEDIUM"
    assert finding.references  # default reference filled in
    assert finding.remediation


def test_plain_nxdomain_without_cname_not_flagged():
    record = ResolvedRecord(
        name="ghost.example.com", resolved=False, dns_status=DnsStatus.NXDOMAIN
    )
    assert detect_dangling_cname(record, SERVICES, FakeSyncResolver()) == []


# ----------------------- Detector 3: NS delegation -----------------------


def _ns_record():
    return ResolvedRecord(
        name="delegated.example.com",
        resolved=False,
        dns_status=DnsStatus.NXDOMAIN,
        ns=["ns1.expired-domain.test", "ns2.expired-domain.test"],
    )


def test_ns_delegation_all_nameservers_dead():
    findings = detect_ns_delegation(_ns_record(), FakeSyncResolver())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "NS_DELEGATION"
    assert finding.confidence == "MEDIUM"
    assert finding.severity == "HIGH"
    assert finding.subdomain == "delegated.example.com"


def test_ns_delegation_one_alive_not_flagged():
    resolver = FakeSyncResolver({("ns1.expired-domain.test", "A"): [FakeAddr("1.1.1.1")]})
    assert detect_ns_delegation(_ns_record(), resolver) == []


def test_ns_delegation_requires_resolver():
    assert detect_ns_delegation(_ns_record(), None) == []


# ------------------------ Detector 4: dangling A ------------------------


A_PAGE_SERVICE = ServiceFingerprint(
    service="Legacy Cloud VM",
    cname_patterns=[],  # pattern-less = A-page fingerprint (detector 4)
    fingerprints=["There is no app on this instance"],
    status="vulnerable",
    severity="MEDIUM",
    remediation="Verify manually.",
)


def test_dangling_a_disabled_by_default():
    record = _record(
        "vm.example.com",
        status=404,
        body="There is no app on this instance",
        a=["203.0.113.10"],
    )
    assert detect_dangling_a(record, [A_PAGE_SERVICE], DetectionConfig()) == []


def test_dangling_a_enabled_low_confidence():
    config = DetectionConfig(enable_dangling_a=True)
    record = _record(
        "vm.example.com",
        status=404,
        body="There is no app on this instance",
        a=["203.0.113.10"],
    )
    findings = detect_dangling_a(record, [A_PAGE_SERVICE], config)
    assert len(findings) == 1
    assert findings[0].type == "DANGLING_A"
    assert findings[0].confidence == "LOW"


def test_dangling_a_ignores_cname_records():
    config = DetectionConfig(enable_dangling_a=True)
    record = _record(
        "vm.example.com",
        target="vm.example.github.io",
        body="There is no app on this instance",
        a=["203.0.113.10"],
    )
    assert detect_dangling_a(record, [A_PAGE_SERVICE], config) == []
