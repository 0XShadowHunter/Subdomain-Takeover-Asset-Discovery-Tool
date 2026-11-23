# Detection Methodology

## 1. Asset discovery (Phase 1)

| Source | Type | Notes |
|---|---|---|
| crt.sh | passive | Certificate Transparency logs; pure Python; failures are non-fatal |
| subfinder / amass / assetfinder | passive | optional binaries; skipped with a warning when absent |
| Wordlist brute-force | active | async DNS (`dnspython`), 200+ default words, `--wordlist` for bigger lists |

**Wildcard handling:** three random labels are resolved first; if all resolve,
their A/CNAME values become the *wildcard signature*, and candidates whose
values are entirely inside the signature are dropped (same idea as PureDNS).

**Merging:** names are lowercased, wildcards stripped, deduplicated, and each
name keeps the list of sources that reported it. Out-of-zone names are dropped.

## 2. DNS + HTTP facts (Phase 2)

For every subdomain:

- **A / AAAA** queries (chain-following, like a real resolver).
- **Full CNAME chain** walked hop-by-hop (visited set + max depth 10 = loop
  protection). A name whose chain ends on a dead target still counts as
  *resolved* — that combination is the takeover signal.
- **NS** records for delegation detection.
- **HTTP probing** (https first, http fallback): final URL, redirect chain,
  status, `<title>`, response headers, first 2 KB of body, TLS errors.
  HTTP DNS lookups go through the *same configured resolver list*.

DNS status classification: `NOERROR`, `NXDOMAIN`, `NODATA`, `SERVFAIL`,
`TIMEOUT`.

## 3. Detectors (Phase 3)

### Detector 1 — CNAME_FINGERPRINT

`CNAME → service pattern matches` **and** the HTTP title/body contains one of
the service's fingerprint strings (e.g. GitHub Pages' *"There isn't a GitHub
Pages site here."*).

- vulnerable service + fingerprint → **HIGH** confidence, service severity
- edge-case service + fingerprint → **MEDIUM** confidence (manual verification)
- not-vulnerable service → **never flagged**
- generic 404/410 **without** a fingerprint match → **ignored** (FP rule)

### Detector 2 — CNAME_NXDOMAIN (dangling)

Signal from Phase 2: `resolved=True` + `dns_status=NXDOMAIN` + chain longer
than the name itself. The candidate is **re-checked with a second live DNS
query**; inconclusive results (timeout/SERVFAIL) are treated as alive —
conservative by design.

- default **MEDIUM** confidence
- **HIGH** when the target matches a service marked `nxdomain: true`
  (the target itself can be registered)

### Detector 3 — NS_DELEGATION

The record has NS records (zone delegation) and **all** delegated nameservers
fail to resolve → the delegation is stale. Requires the live resolver.
Confidence MEDIUM, severity HIGH.

### Detector 4 — DANGLING_A (best-effort, disabled by default)

A-only records whose page matches a configured pattern-less fingerprint.
Enable via `detection.enable_dangling_a: true` in `fingerprints.yaml`.
Always LOW confidence.

## 4. Confidence & severity model

| Confidence | Meaning |
|---|---|
| HIGH | Vulnerable service + exact fingerprint match (or claimable NXDOMAIN target) |
| MEDIUM | Dangling signal verified but needs manual confirmation / edge-case service |
| LOW | Best-effort heuristics — review manually |

| Severity | Assigned when |
|---|---|
| CRITICAL | reserved for manual review escalation |
| HIGH | fingerprint-confirmed vulnerable services (GitHub Pages, S3, Heroku, Azure, …) and dangling/NS signals |
| MEDIUM | fingerprint-confirmed services with claim restrictions, DANGLING_A |
| LOW / INFO | edge-case / documentation entries |

## 5. False-positive reduction (summary)

1. Services marked `not-vulnerable` are skipped entirely (CloudFront, Vercel…).
2. Generic 404/410 bodies without a fingerprint match are ignored.
3. Dangling candidates are re-checked before flagging; inconclusive = skip.
4. Wildcard DNS zones are signature-filtered at discovery time.
5. Findings are advisory — evidence + references + remediation are always
   included so a human can verify in minutes.

## References

- can-i-take-over-xyz (fingerprints source of truth)
- OWASP WSTG-CONF-10 — Testing for Subdomain Takeover
- HackerOne/Bugcrowd public takeover reports
