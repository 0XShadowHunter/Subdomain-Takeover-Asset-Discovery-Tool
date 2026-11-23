# Comparison with existing tools

| | **subtake (this tool)** | subjack | subzy | nuclei (takeover templates) | dnsReaper |
|---|---|---|---|---|---|
| Language | Python 3.10+ | Go | Go | Go | Python |
| Windows support | first-class (tested) | yes (binary) | yes (binary) | yes (binary) | mostly POSIX-oriented |
| Asset discovery (enumeration) | ✅ built-in (crt.sh + binaries + brute-force) | ❌ (input: list) | ❌ | ❌ | ❌ (input: list/zone file) |
| DNS resolution + HTTP probing | ✅ built-in, single pass | partial | partial | via templates | ✅ |
| CNAME fingerprint detection | ✅ 25 services, YAML-editable | ✅ hardcoded set | ✅ hardcoded set | ✅ community templates | ✅ ~50 signatures |
| Dangling-CNAME (NXDOMAIN) detection | ✅ + live re-check | ❌ | ❌ | ❌ | partial |
| NS-delegation detection | ✅ | ❌ | ❌ | ❌ | partial |
| Wildcard filtering | ✅ signature-based | ❌ | ❌ | ❌ | ✅ |
| Confidence/severity scoring | ✅ HIGH/MEDIUM/LOW × 5 severities | ❌ boolean | ❌ boolean | severity per template | partial |
| False-positive controls | explicit rules (re-check, ignore generic 404, not-vulnerable list) | limited | limited | template-dependent | ✅ |
| Remediation advice per finding | ✅ | ❌ | ❌ | ❌ | ✅ (basic) |
| Reports | JSON/CSV/Markdown/HTML | stdout | stdout | stdout/JSON | stdout/CSV/JSON |
| Phase-by-phase JSON contracts (team handoff) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Ethical detect-and-report guarantee | ✅ enforced by design | — | — | — | — |

## Positioning

- **subjack/subzy** are fast checkers but take a *list of hosts* as input and
  hard-code their fingerprints; they don't discover assets and don't produce
  structured reports.
- **nuclei** is a general-purpose scanner — its takeover templates are strong
  for the HTTP-fingerprint step but it has no discovery, no CNAME-chain logic,
  and no NXDOMAIN/dangling analysis on its own.
- **dnsReaper** is the closest in spirit (Python, broad signatures) but is
  oriented to single-shot DNS analysis and lacks the discovery pipeline,
  wildcard-filtered brute force, staged contracts, and multi-format reporting
  this tool ships.

**subtake's niche:** an end-to-end, cross-platform, graduation-project-grade
pipeline (discovery → resolution → detection → reports) with explicit data
contracts, conservative confidence scoring, and an editable YAML fingerprint
base — while staying strictly detect-and-report.
