# Limitations & Assumptions

## Detection limitations

1. **Fingerprints drift.** Service responses (and their 404 pages) change over
   time. The fingerprint table is data (`config/fingerprints.yaml`) sourced
   from can-i-take-over-xyz as of 2026-11 and must be kept updated.
2. **MEDIUM ≠ confirmed.** Dangling-CNAME and NS findings are advisory;
   a human must confirm exploitability before treating them as real.
3. **Wildcard zones** can hide real findings: if the wildcard answer matches
   the signature of a *real* host's answer, that real host is filtered too
   (standard trade-off, same as PureDNS-class tools).
4. **Detector 4 (DANGLING_A) is disabled by default** and heuristic — cloud
   providers recycle IPs constantly; it only fires on configured page
   fingerprints, always LOW confidence.
5. **NS-delegation detection needs live DNS** during detection (Phase 2
   contract does not carry nameserver resolvability).
6. **No exploitation, ever.** The tool cannot and will not verify a takeover
   by claiming the resource. Evidence = fingerprints + DNS state only.
7. **HTTP probing depth**: first 2 KB of the body only (title/fingerprint
   matching); JS-rendered pages may lack the fingerprint in raw HTML.
8. **Auth-walled sources** (VT, Shodan, SecurityTrails…) are reserved in
   settings but not yet implemented — passive coverage relies on crt.sh +
   optional local binaries.

## Environmental assumptions

- Windows 10/11 and Linux (Kali/Ubuntu/Debian) with Python 3.10+.
- Outbound DNS + HTTPS available. Rate limits of public resolvers apply
  (`--rate` and `--threads` exist for polite scanning).
- crt.sh is occasionally overloaded (HTTP 502) — the tool continues without
  it; retry later for maximum coverage.

## Verification status

- Windows 11 + Python 3.13: full manual verification (all phases + reports).
- Linux: verified by design + unit tests + CI matrix (`ubuntu-latest`,
  Python 3.10–3.12). A manual Kali run is a remaining team task (see
  `AGENT_PLAN.md` Phase 4 handoff notes).
- Screenshots for the README are intentionally left for the team to capture
  on their own terminals.
