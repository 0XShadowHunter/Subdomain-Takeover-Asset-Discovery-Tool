# SQLite Database Schema (ERD)

> Requirement (Project 07 — Phase 4): *"Store all discovered subdomains,
> resolved IP addresses, CNAME records, and flagged takeover vulnerabilities
> into a local SQLite database."*
>
> Implementation: `src/storage/sqlite_store.py` (pure stdlib `sqlite3`) —
> one database file per output folder: **`subtake.db`**.

## Entity-Relationship Diagram

```
┌──────────────────────────┐
│         scans            │
├──────────────────────────┤
│ id          INTEGER  PK  │───┐        one row per tool run
│ target      TEXT         │   │        e.g. 'amit-learning.com'
│ started_at  TEXT          │   │        ISO-8601 UTC
└──────────────────────────┘   │
        │ 1                    │
        │                      │
        ├──────────────┬───────┴──────────┬─────────────────────┐
        │ N            │ N                │ N                   │ N
┌───────▼──────────────┐ ┌───────▼──────────────┐ ┌──▼───────────────────┐
│      subdomains      │ │     dns_records      │ │      findings        │
├──────────────────────┤ ├──────────────────────┤ ├──────────────────────┤
│ id       INTEGER  PK │ │ id       INTEGER  PK │ │ id       INTEGER  PK │
│ scan_id  INTEGER  FK │ │ scan_id  INTEGER  FK │ │ scan_id  INTEGER  FK │
│ name     TEXT        │ │ name        TEXT     │ │ subdomain   TEXT     │
│ source   TEXT        │ │ resolved    INTEGER  │ │ type        TEXT     │
└──────────────────────┘ │ dns_status  TEXT     │ │ service     TEXT     │
 "discovered             │ ip_addresses TEXT*   │ │ cname_target TEXT    │
  subdomains"            │ ipv6        TEXT*    │ │ evidence    TEXT     │
                         │ cname_chain TEXT*    │ │ confidence  TEXT     │
                         │ ns          TEXT*    │ │ severity    TEXT     │
                         │ http_status INTEGER  │ │ remediation TEXT     │
                         │ http_title  TEXT     │ │ ref_links   TEXT     │
                         │ http_error  TEXT     │ └──────────────────────┘
                         └──────────────────────┘  "flagged takeover
                          "resolved IPs + CNAME     vulnerabilities"
                           records"
```

\* Multi-value columns are comma/arrow-joined strings
(`ip_addresses="1.2.3.4,5.6.7.8"`, `cname_chain="a -> b -> c"`).

## Requirement → Column mapping

| Requirement phrase | Table.column |
|---|---|
| "all discovered subdomains" | `subdomains.name` (+ `subdomains.source` per OSINT source) |
| "resolved IP addresses" | `dns_records.ip_addresses`, `dns_records.ipv6` |
| "CNAME records" | `dns_records.cname_chain` (full chain, arrow-joined) |
| "flagged takeover vulnerabilities" | `findings.*` (type, evidence, confidence, severity, remediation) |

## Tables

### `scans` — one row per tool run
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | autoincrement |
| target | TEXT | the scanned domain |
| started_at | TEXT | ISO-8601 UTC timestamp |

### `subdomains` — one row per (subdomain, source) pair
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| scan_id | INTEGER FK → scans.id | |
| name | TEXT | e.g. `api.amit-learning.com` |
| source | TEXT | `crtsh` / `bruteforce` / `subfinder` / … |

### `dns_records` — one row per resolved subdomain
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| scan_id | INTEGER FK → scans.id | |
| name | TEXT | |
| resolved | INTEGER | 0/1 |
| dns_status | TEXT | NOERROR / NXDOMAIN / SERVFAIL / TIMEOUT / NODATA |
| ip_addresses | TEXT | A records, comma-joined |
| ipv6 | TEXT | AAAA records, comma-joined |
| cname_chain | TEXT | full chain, arrow-joined |
| ns | TEXT | delegated nameservers, comma-joined |
| http_status | INTEGER NULL | e.g. 200 / 404 |
| http_title | TEXT NULL | page `<title>` |
| http_error | TEXT NULL | probe error (TLS, timeout, …) |

### `findings` — one row per flagged vulnerability
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| scan_id | INTEGER FK → scans.id | |
| subdomain | TEXT | |
| type | TEXT | CNAME_FINGERPRINT / CNAME_NXDOMAIN / NS_DELEGATION / DANGLING_A |
| service | TEXT | e.g. `GitHub Pages` |
| cname_target | TEXT NULL | |
| evidence | TEXT | matched fingerprint / re-check proof |
| confidence | TEXT | HIGH / MEDIUM / LOW |
| severity | TEXT | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| remediation | TEXT | advice (the tool never exploits anything) |
| ref_links | TEXT | reference URLs, pipe-joined |

## Example queries

```bash
# All HIGH-confidence findings from every scan
sqlite3 data/output/subtake.db \
  "SELECT s.target, f.subdomain, f.severity FROM findings f \
   JOIN scans s ON s.id = f.scan_id WHERE f.confidence='HIGH'"

# Every subdomain of the latest scan with its IPs
sqlite3 data/output/subtake.db \
  "SELECT d.name, d.ip_addresses, d.http_status FROM dns_records d \
   WHERE d.scan_id = (SELECT MAX(id) FROM scans)"

# Subdomains per source (OSINT vs brute-force)
sqlite3 data/output/subtake.db \
  "SELECT source, COUNT(*) FROM subdomains GROUP BY source"
```

## Integration points

- `python -m src.cli scan` — one `scans` row; phases 1/2/3 written as they complete
- `discover` / `resolve` / `detect` — each writes its phase under a fresh `scans` row
- GUI (`▶ Start scan`) — same writes, progress shown in the live log
- `PyInstaller` exe — bundles `sqlite3` automatically (stdlib)
