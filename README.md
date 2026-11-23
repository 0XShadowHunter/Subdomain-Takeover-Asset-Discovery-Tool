# Subdomain Takeover & Asset Discovery Tool (subtake)

A cross-platform (**Windows / Linux / Kali**) Python tool that:

1. **Discovers assets** — enumerates the subdomains of a target domain
   (crt.sh + optional external binaries + wordlist brute-force with wildcard
   detection).
2. **Detects subdomain takeover risk** — finds dangling DNS records pointing
   at deprovisioned services and reports them with evidence, confidence,
   severity, and remediation advice.

> ⚠️ **AUTHORIZED USE ONLY.** Use this tool only on domains you **own** or have
> **written permission** to test (in-scope bug bounty / authorized pentest /
> lab targets). The tool **detects and reports only** — it never claims,
> registers, or exploits any resource. The authors are not responsible for
> misuse.

## How it works

```
Target Domain
     │
     ▼
[1] discover   subdomain enumeration (crt.sh, optional subfinder/amass,
               wordlist brute-force + wildcard detection)
     │         → data/output/phase1_subdomains.json
     ▼
[2] resolve    A/AAAA/CNAME-chain/NS resolution + HTTP probing
     │         → data/output/phase2_resolved.json
     ▼
[3] detect     4 detectors + confidence/severity scoring
     │         → data/output/phase3_findings.json
     ▼
[4] reports    JSON / CSV / Markdown / HTML (self-contained, Jinja2)
```

Every stage also runs standalone (`discover`, `resolve`, `detect` commands) —
phases communicate only through the JSON contracts in `AGENT_PLAN.md` §2.

## Requirements

- **Python 3.10+** (Windows, Linux, macOS) — no compiler needed; all
  dependencies ship prebuilt wheels.
- External tools (subfinder, amass, httpx, nuclei…) are **optional**
  accelerators — the tool is fully functional with Python only.

## Install

### Windows (PowerShell)

```powershell
.\scripts\setup.ps1
.\.venv\Scripts\Activate.ps1
python -m src.cli --help
```

If script execution is blocked: `powershell -ExecutionPolicy Bypass -File scripts\setup.ps1`

### Linux / Kali (bash)

```bash
bash scripts/setup.sh
source .venv/bin/activate
python -m src.cli --help
```

### Optional: install external tools

These are **not required**. When present, they speed up enumeration; when
absent, the tool logs a warning and continues.

| Tool | Kali / Debian | Windows |
|---|---|---|
| amass | `sudo apt install amass` | download from [OWASP Amass releases](https://github.com/owasp-amass/amass/releases) |
| subfinder | `sudo apt install subfinder` or `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | download from [subfinder releases](https://github.com/projectdiscovery/subfinder/releases) |
| httpx (ProjectDiscovery) | `sudo apt install httpx-toolkit` (the tool auto-detects the `httpx-toolkit` name) | download from [httpx releases](https://github.com/projectdiscovery/httpx/releases) |
| nuclei | `sudo apt install nuclei` | download from [nuclei releases](https://github.com/projectdiscovery/nuclei/releases) |

Windows binaries: put the `.exe` anywhere on `PATH` (e.g.
`C:\Tools\` added to the user `PATH`).

### Install like a program (Windows — one-click "Setup" button)

Double-click **`scripts\install.bat`**. That single click:

- installs the program: the **`subtake`** and **`subtake-gui`** commands work
  from any terminal (with the venv activated)
- creates a **"subtake GUI"** desktop shortcut

Power-user flags:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -BuildExe -Shortcut
# additionally builds dist\subtake.exe — a standalone ~19 MB program that runs
# WITHOUT Python installed. It carries the SUBTAKE brand icon and is a
# *windowed* build: double-clicking it opens the GUI with NO console window.
# From a terminal the CLI still works — the exe attaches to the parent console
# (config, wordlist, report templates and the logo are bundled inside).
# Built with PyInstaller inside the project venv only.
```

## GUI (point-and-click, no terminal skills needed)

```powershell
python -m src.cli gui      # or:  subtake-gui   |   double-click dist\subtake.exe
```

Enter a target domain, tick the options, press **▶ Start scan** — the live
log streams into the window, findings appear in a severity-colored table, and
a button opens the output folder with the generated reports.

## Usage

### One command — full pipeline + reports

```bash
python -m src.cli scan --domain example.com --format all
```

Common options:

```bash
python -m src.cli scan --domain example.com \
    --format html,csv,markdown \
    --threads 50 \
    --timeout 10 \
    --skip-brute \
    --wordlist my-wordlist.txt \
    --output-dir results
```

### Stage-by-stage

```bash
python -m src.cli discover --domain example.com                 # phase 1
python -m src.cli resolve                                       # phase 2 (uses phase1 output)
python -m src.cli detect                                        # phase 3 (uses phase2 output)
python -m src.cli detect --fingerprints my-fingerprints.yaml    # custom fingerprints
```

Add `-v` (before the subcommand) for debug logging. Every run prints the
authorization warning first — that's by design.

### Docker (optional)

```bash
docker build -t subtake .
docker run --rm subtake scan --domain example.com --format all
```

## Output files — one main results folder, CLI and GUI separated

All saved scan data (SQLite + artifacts) lives under **`data/results/`**, with a
dedicated sub-area per origin so CLI and GUI scans never mix:

```
data/results/
├── cli/                      ← scans started from the command line
│   └── example.com/
│       ├── phase1_subdomains.json
│       ├── phase2_resolved.json
│       ├── phase3_findings.json
│       ├── subtake.db        ← SQLite: scan history of THIS domain
│       └── report.html / .csv / .md / .json
└── gui/                      ← scans started from the GUI (or the exe double-click)
    └── amit-learning.com/
        └── subtake.db …
```

| File | Content |
|---|---|
| `phase1_subdomains.json` | discovered subdomains + their sources |
| `phase2_resolved.json` | DNS records (A/AAAA/CNAME chain/NS) + HTTP probe data |
| `phase3_findings.json` | findings with evidence, confidence, severity, remediation |
| `subtake.db` | **SQLite database** — every scan of this domain (subdomains, IPs, CNAME chains, findings) |
| `report.html` | human-readable report — includes the **full discovered-subdomain list** + findings (severity-sorted) |
| `report.csv` / `.md` / `.json` | findings-focused exports |
| **`report.xlsx`** | Excel workbook: Summary / **Subdomains sheet (every discovered subdomain)** / severity-colored Findings — enable with `--format excel` or `all` |

Query the database:

```bash
sqlite3 data/results/cli/example.com/subtake.db "SELECT subdomain, severity, remediation FROM findings WHERE confidence='HIGH'"
```

In the GUI the output folder follows the typed domain automatically
(`data/results/gui/<domain>/`) until you type your own. The standalone exe
detects the project checkout (it walks up from `dist/` looking for
`config/settings.yaml`) and saves into the **project's** `data/results/` —
when the exe is moved to a machine without the project, it falls back to
keeping results next to itself. Override any location with `--output-dir`
(scan) / `--db` (clean).

### Deleting stored results (`clean`)

```bash
# Clear the domain's scan history from its SQLite database (confirmed)
python -m src.cli clean --domain example.com

# Also delete its whole results folder
python -m src.cli clean --domain example.com --purge-files

# Non-interactive (CI/scripts): skip the prompts
python -m src.cli clean --domain example.com --yes --purge-files
```

Every deletion shows exactly what will be removed first, and refuses to run
in non-interactive sessions unless `--yes` is given. The GUI has a
**🗑 Clear saved results** button that does the same with confirmation
dialogs (folder deletion is restricted to the default per-domain folder).

## Configuration

- `config/settings.yaml` — timeouts, concurrency, public DNS resolvers,
  per-source toggles. API keys must come from **environment variables**, never
  this file.
- `config/fingerprints.yaml` — the takeover service fingerprints (reference:
  [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)).
  Editable without touching code: add a service, change fingerprints, flip
  `status: vulnerable | edge-case | not-vulnerable`.

## Tests

```bash
python -m pytest          # 130 tests — all network/subprocess calls mocked
ruff check src tests      # lint (CI runs both on Windows + Ubuntu, py3.10–3.12)
```

## Troubleshooting

| Symptom | Explanation / fix |
|---|---|
| `crt.sh returned HTTP 502` | crt.sh is often overloaded; the run continues without it. Retry later or disable the source in `settings.yaml`. |
| `xxx is not installed — skipping` | Optional external tool missing — purely informational. |
| A wildcard domain floods results | It shouldn't: brute-force probes random labels and filters wildcard answers. Report it if you see this. |
| PowerShell blocks `Activate.ps1` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` or run with `-ExecutionPolicy Bypass`. |
| DNS results differ across machines | The tool uses the configured resolvers (1.1.1.1/8.8.8.8/9.9.9.9), never the OS config — results should match. Check `--resolvers`. |
| `httpx` not detected on Kali | Kali ships it as `httpx-toolkit`; the tool checks both names automatically. |

## Documentation

- [docs/architecture.md](docs/architecture.md) — module map, data flow, design decisions
- [docs/database.md](docs/database.md) — SQLite schema (ERD), table docs, example queries
- [docs/methodology.md](docs/methodology.md) — detection signals, confidence/severity model, FP reduction
- [docs/limitations.md](docs/limitations.md) — what this tool can and cannot do
- [docs/comparison.md](docs/comparison.md) — vs subjack / subzy / nuclei / dnsReaper
- [docs/demo-defense.md](docs/demo-defense.md) — graduation demo scenario & presentation outline

## Ethics & scope

Detection and reporting only — no claiming, no registration, no exploitation.
Remediation text is advice. Fingerprints data: [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).
Test only on owned domains or authorized targets (e.g. `example.com`,
`*.invalid`, your own lab).
