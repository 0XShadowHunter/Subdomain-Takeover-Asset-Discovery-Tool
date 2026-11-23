"""Async DNS helpers built on dnspython's asyncio API (AGENT_PLAN.md §1.1 #4).

- Uses an explicit resolver list from settings (1.1.1.1 / 8.8.8.8 / 9.9.9.9) —
  never ``/etc/resolv.conf`` or the Windows resolver config — so results match
  on Windows and Linux.
- No aiodns/uvloop (both problematic on Windows).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver

log = logging.getLogger(__name__)


class DnsStatus:
    """DNS status classification (values shared with the Phase 2 contract)."""

    NOERROR = "NOERROR"
    NXDOMAIN = "NXDOMAIN"
    SERVFAIL = "SERVFAIL"
    TIMEOUT = "TIMEOUT"
    NODATA = "NODATA"


@dataclass
class DnsAnswer:
    """Result of resolving one name."""

    status: str
    a: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def resolved(self) -> bool:
        return self.status == DnsStatus.NOERROR and bool(self.a or self.cname)


def build_resolver(
    resolvers: list[str],
    timeout: float = 10.0,
    attempts: int = 2,
) -> dns.asyncresolver.Resolver:
    """Build an isolated async resolver bound to the given nameservers.

    ``configure=False`` guarantees the OS resolver configuration is ignored.
    """
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [str(r) for r in resolvers]
    resolver.timeout = timeout
    resolver.lifetime = timeout * max(1, attempts)
    resolver.attempts = attempts
    return resolver


async def resolve_name(resolver: dns.asyncresolver.Resolver, name: str) -> DnsAnswer:
    """Resolve A/CNAME for one name, classify the status, and never raise.

    A name whose CNAME *target* is dead (dangling) still counts as resolved
    because the name itself exists — Phases 2/3 need it in the output. The
    CNAME fallback also covers names that have no A record at all.
    """
    a: list[str] = []
    a_status = DnsStatus.NOERROR
    try:
        resp = await resolver.resolve(name, "A")
        a = [r.address for r in resp]
    except dns.resolver.NXDOMAIN:
        a_status = DnsStatus.NXDOMAIN
    except dns.resolver.NoAnswer:
        a_status = DnsStatus.NODATA
    except dns.exception.Timeout as exc:
        return DnsAnswer(status=DnsStatus.TIMEOUT, error=str(exc))
    except (dns.resolver.NoNameservers, OSError) as exc:
        return DnsAnswer(status=DnsStatus.SERVFAIL, error=str(exc))

    if a_status == DnsStatus.NOERROR and a:
        return DnsAnswer(status=DnsStatus.NOERROR, a=a)

    # No usable A record — is there a CNAME? This covers plain NODATA names
    # and dangling CNAMEs, where the A lookup fails with NXDOMAIN because the
    # *target* of the chain is dead while the name itself still exists.
    try:
        resp = await resolver.resolve(name, "CNAME")
        cname = [r.target.to_text().rstrip(".").lower() for r in resp]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        cname = []
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError) as exc:
        return DnsAnswer(status=DnsStatus.TIMEOUT, error=str(exc))

    if cname:
        return DnsAnswer(status=DnsStatus.NOERROR, cname=cname)
    return DnsAnswer(status=a_status)
