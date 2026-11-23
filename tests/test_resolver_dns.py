"""Phase 2 DNS resolution tests — dnspython fully mocked with a fake resolver."""

import asyncio

import dns.exception
import dns.resolver

from src.discovery.dns_client import DnsStatus
from src.resolver.dns_resolver import resolve_record


class FakeA:
    def __init__(self, address):
        self.address = address


class _FakeDnsName:
    def __init__(self, host):
        self.host = host

    def to_text(self):
        return self.host + "."


class FakeTarget:
    """Stands in for dnspython CNAME/NS rdata (rdata.target.to_text())."""

    def __init__(self, host):
        self.target = _FakeDnsName(host)


class FakeResolver:
    """(name, rdtype) -> values | Exception. Missing keys raise NoAnswer."""

    def __init__(self, table=None):
        self.table = dict(table or {})

    async def resolve(self, name, rdtype):
        value = self.table.get((name, rdtype))
        if value is None:
            raise dns.resolver.NoAnswer()
        if isinstance(value, Exception):
            raise value
        return value


def test_plain_a_record():
    resolver = FakeResolver({("www.example.com", "A"): [FakeA("93.184.216.34")]})
    record = asyncio.run(resolve_record(resolver, "www.example.com"))
    assert record.resolved is True
    assert record.dns_status == DnsStatus.NOERROR
    assert record.a == ["93.184.216.34"]
    assert record.aaaa == []
    assert record.cname_chain == ["www.example.com"]


def test_cname_to_live_target():
    resolver = FakeResolver(
        {
            # The A query follows the chain in real dnspython — simulated here.
            ("blog.example.com", "A"): [FakeA("185.199.108.153")],
            ("blog.example.com", "CNAME"): [FakeTarget("example.github.io")],
        }
    )
    record = asyncio.run(resolve_record(resolver, "blog.example.com"))
    assert record.resolved is True
    assert record.dns_status == DnsStatus.NOERROR
    assert record.cname_chain == ["blog.example.com", "example.github.io"]
    assert record.a == ["185.199.108.153"]


def test_dangling_cname_target_nxdomain():
    resolver = FakeResolver(
        {
            ("blog.example.com", "A"): dns.resolver.NXDOMAIN(),
            ("blog.example.com", "CNAME"): [FakeTarget("dead.example.github.io")],
            ("dead.example.github.io", "CNAME"): dns.resolver.NXDOMAIN(),
        }
    )
    record = asyncio.run(resolve_record(resolver, "blog.example.com"))
    # The name exists via CNAME but the chain ends on a dead target —
    # exactly the signal Phase 3's dangling-CNAME detector needs.
    assert record.resolved is True
    assert record.dns_status == DnsStatus.NXDOMAIN
    assert record.cname_chain == ["blog.example.com", "dead.example.github.io"]
    assert record.a == []


def test_missing_name_nxdomain():
    resolver = FakeResolver({("x.example.com", "A"): dns.resolver.NXDOMAIN()})
    record = asyncio.run(resolve_record(resolver, "x.example.com"))
    assert record.resolved is False
    assert record.dns_status == DnsStatus.NXDOMAIN


def test_timeout_status():
    resolver = FakeResolver({("y.example.com", "A"): dns.exception.Timeout()})
    record = asyncio.run(resolve_record(resolver, "y.example.com"))
    assert record.resolved is False
    assert record.dns_status == DnsStatus.TIMEOUT


def test_servfail_status():
    resolver = FakeResolver({("z.example.com", "A"): dns.resolver.NoNameservers()})
    record = asyncio.run(resolve_record(resolver, "z.example.com"))
    assert record.resolved is False
    assert record.dns_status == DnsStatus.SERVFAIL


def test_nodata_name():
    # Name exists (no A, no CNAME) — e.g. a TXT-only host.
    record = asyncio.run(resolve_record(FakeResolver(), "txt.example.com"))
    assert record.resolved is False
    assert record.dns_status == DnsStatus.NODATA


def test_cname_loop_protection():
    resolver = FakeResolver(
        {
            ("a.example.com", "A"): dns.resolver.NoAnswer(),
            ("a.example.com", "CNAME"): [FakeTarget("b.example.com")],
            ("b.example.com", "CNAME"): [FakeTarget("a.example.com")],
        }
    )
    record = asyncio.run(resolve_record(resolver, "a.example.com"))
    # Terminates, shows the loop in the chain, and never claims resolution.
    assert record.cname_chain == ["a.example.com", "b.example.com", "a.example.com"]
    assert record.resolved is True
    assert record.dns_status == DnsStatus.NODATA


def test_ns_delegation_recorded():
    resolver = FakeResolver(
        {
            ("delegated.example.com", "A"): dns.resolver.NoAnswer(),
            ("delegated.example.com", "NS"): [FakeTarget("ns1.child.example.com")],
        }
    )
    record = asyncio.run(resolve_record(resolver, "delegated.example.com"))
    assert record.ns == ["ns1.child.example.com"]
    assert record.resolved is False
    assert record.dns_status == DnsStatus.NODATA


def test_aaaa_recorded():
    resolver = FakeResolver({("v6.example.com", "AAAA"): [FakeA("2606:2800:220:1::1")]})
    record = asyncio.run(resolve_record(resolver, "v6.example.com"))
    assert record.aaaa == ["2606:2800:220:1::1"]
    assert record.resolved is True
    assert record.dns_status == DnsStatus.NOERROR
