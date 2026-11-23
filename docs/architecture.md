# Architecture

## High-level data flow

```
                    ┌─────────────────────────────────────────────┐
                    │                 src/cli.py                  │
                    │   discover │ resolve │ detect │ scan        │
                    └──────┬───────────┬──────────┬───────────────┘
                           │           │          │
        ┌──────────────────▼─┐   ┌─────▼──────┐ ┌─▼────────────────┐
        │ discovery/ (Ph 1)  │   │ resolver/  │ │ detection/ (Ph 3)│
        │ validators         │   │ (Ph 2)     │ │ fingerprints.py  │
        │ crtsh.py           │   │ dns_resolver│ detectors.py    │
        │ external_tools.py  │   │ http_probe │  │ analyze.py       │
        │ dns_client.py      │   │ rate_limit │  │ pipeline.py      │
        │ bruteforce.py      │   │ pipeline   │  └──────┬───────────┘
        │ pipeline.py        │   └─────┬──────┘         │
        └──────────┬─────────┘         │                │
                   ▼                   ▼                ▼
          phase1_subdomains.json  phase2_resolved.json  phase3_findings.json
                   │                   │                │
                   └───────────────────┴────────────────┤
                                                        ▼
                                        reporting/ (Ph 4) → report.{json,csv,md,html}
```

Phases communicate **only** through JSON contract files (data contracts in
`AGENT_PLAN.md` §2), so each stage can run standalone and team members can work
independently.

## Module responsibilities

| Module | Responsibility |
|---|---|
| `src/models.py` | The three data contracts as dataclasses with tolerant `to_dict`/`from_dict` |
| `src/utils/paths.py` | Single source of truth for all file locations (pathlib only) + settings defaults |
| `src/utils/platform.py` | OS detection, `find_tool()` with aliases (`httpx-toolkit`), safe subprocess, event-loop policy |
| `src/discovery/` | Phase 1: validation, crt.sh client, optional binary wrappers, async brute-force + wildcard detection, merge |
| `src/resolver/` | Phase 2: A/AAAA/CNAME-chain/NS resolution with status classification, HTTP probing, rate limiting |
| `src/detection/` | Phase 3: fingerprint loading/matching, four detectors, orchestration + scoring |
| `src/reporting/` | Phase 4: JSON/CSV/Markdown/HTML reports (Jinja2, severity-sorted) |
| `src/cli.py` | argparse CLI + Rich output + authorization warning |

## Key design decisions

1. **Pure-Python first.** External binaries are optional accelerators located
   via `shutil.which` with alias lists; missing tools degrade to warnings.
2. **Explicit DNS resolvers everywhere.** Both the DNS layer (`dnspython`,
   `configure=False`) and the HTTP layer (a custom
   `aiohttp.abc.AbstractResolver` backed by the same dnspython resolver) use
   the configured list (1.1.1.1 / 8.8.8.8 / 9.9.9.9) — never the OS resolver
   config — so results match across Windows/Linux.
3. **asyncio only, no uvloop/aiodns** (problematic on Windows). On Windows the
   selector event-loop policy is set in one helper.
4. **Fail-soft per record.** Every per-host error (DNS timeout, bad TLS,
   unexpected exception) is captured into that record's fields; one bad host
   can never crash a scan.
5. **Contracts first.** Models are tolerant of missing keys, so newer outputs
   still parse with older code (and vice versa) during team handoffs.
6. **Fingerprints as data.** Services live in YAML (status
   vulnerable/edge-case/not-vulnerable, patterns, strings) — no code change
   needed to track the ecosystem.
7. **Detect & report only.** No module can claim, register, or exploit a
   resource; remediation is advice text.
