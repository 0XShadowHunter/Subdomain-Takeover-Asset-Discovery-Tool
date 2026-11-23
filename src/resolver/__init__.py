"""Phase 2 — DNS resolution & HTTP probing.

Reads phase1_subdomains.json, resolves every subdomain (A/AAAA, full CNAME
chain with loop protection, NS), probes HTTP/HTTPS, and writes the Phase 2
contract (phase2_resolved.json).
"""
