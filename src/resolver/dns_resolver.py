"""Phase 2 DNS resolution: A/AAAA, full CNAME chain, NS, status classification.

Rules (AGENT_PLAN.md §4):
- Resolvers come from settings (1.1.1.1 / 8.8.8.8 / 9.9.9.9) via
  ``build_resolver(configure=False)`` — never the OS resolver config.
- The full CNAME chain is followed with loop protection (visited set + max
  depth).
- A CNAME whose chain ends on a dead target is reported as ``dns_status=
  NXDOMAIN`` with ``resolved=True`` — that combination is the dangling-record
  signal Phase 3 relies on.
"""

from __future__ import annotations

import logging

import dns.exception
import dns.resolver

from src.discovery.dns_client import DnsStatus
from src.models import ResolvedRecord

log = logging.getLogger(__name__)

#: Hard cap on CNAME chain length (loop protection; real chains are short).
MAX_CHAIN_DEPTH = 10


async def _query(resolver, name: str, rdtype: str) -> tuple[list[str], str, str | None]:
    """Run one DNS query; return (values, status, error) and never raise."""
    try:
        resp = await resolver.resolve(name, rdtype)
    except dns.resolver.NXDOMAIN:
        return [], DnsStatus.NXDOMAIN, None
    except dns.resolver.NoAnswer:
        return [], DnsStatus.NODATA, None
    except dns.exception.Timeout as exc:
        return [], DnsStatus.TIMEOUT, str(exc)
    except (dns.resolver.NoNameservers, OSError) as exc:
        return [], DnsStatus.SERVFAIL, str(exc)
    if rdtype in ("A", "AAAA"):
        values = [r.address for r in resp]
    else:  # CNAME / NS rdata are domain-name objects
        values = [r.target.to_text().rstrip(".").lower() for r in resp]
    return values, DnsStatus.NOERROR, None


async def follow_cname_chain(resolver, name: str, max_depth: int = MAX_CHAIN_DEPTH):
    """Walk CNAME records hop by hop.

    Returns ``(chain, last_status, loop_detected)``. ``chain`` always starts
    with ``name``; ``last_status`` is the CNAME-query status of the final hop —
    it is NXDOMAIN when the chain ends on a dead target (dangling CNAME).
    """
    chain = [name]
    visited = {name}
    last_status = DnsStatus.NODATA
    loop_detected = False
    current = name
    for _ in range(max_depth):
        targets, status, _ = await _query(resolver, current, "CNAME")
        last_status = status
        if not targets:
            break  # no CNAME here (or the name is dead) — end of the walk
        target = targets[0]
        chain.append(target)
        if target in visited:
            loop_detected = True
            break
        visited.add(target)
        current = target
    else:
        log.warning("CNAME chain for %s hit the %d-hop limit", name, max_depth)
    return chain, last_status, loop_detected


async def resolve_record(
    resolver, name: str, max_depth: int = MAX_CHAIN_DEPTH
) -> ResolvedRecord:
    """Resolve one subdomain into a Phase 2 ResolvedRecord. Never raises."""
    a, a_status, _ = await _query(resolver, name, "A")
    aaaa, _aaaa_status, _ = await _query(resolver, name, "AAAA")
    ns, _ns_status, _ = await _query(resolver, name, "NS")
    chain, last_status, loop = await follow_cname_chain(resolver, name, max_depth)

    record = ResolvedRecord(name=name, a=a, aaaa=aaaa, ns=ns, cname_chain=chain)

    if a or aaaa:
        record.dns_status = DnsStatus.NOERROR
        record.resolved = True
    elif len(chain) > 1:
        # The name exists via CNAME even when the chain is broken elsewhere.
        record.resolved = True
        if last_status == DnsStatus.NXDOMAIN:
            record.dns_status = DnsStatus.NXDOMAIN  # dangling CNAME — takeover signal
        elif loop:
            record.dns_status = DnsStatus.NODATA
        else:
            record.dns_status = DnsStatus.NOERROR
    elif a_status == DnsStatus.NXDOMAIN:
        record.dns_status = DnsStatus.NXDOMAIN
    elif a_status in (DnsStatus.TIMEOUT, DnsStatus.SERVFAIL):
        record.dns_status = a_status
    else:
        record.dns_status = DnsStatus.NODATA
    return record
