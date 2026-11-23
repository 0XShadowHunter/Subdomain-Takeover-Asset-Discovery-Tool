"""Command-line interface: ``python -m src.cli <command>``.

Commands map 1:1 to the phases in AGENT_PLAN.md:
  discover → Phase 1 (implemented here)
  resolve  → Phase 2 (placeholder until Phase 2 lands)
  detect   → Phase 3 (placeholder until Phase 3 lands)
  scan     → full pipeline + reports (placeholder until Phase 4 lands)
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from rich.prompt import Confirm
from rich.table import Table

from src import __version__
from src.detection.pipeline import Phase3InputError, load_phase2_file, run_detection
from src.discovery.pipeline import enumerate_subdomains
from src.discovery.validators import InvalidDomainError, normalize_domain
from src.reporting.reports import generate_reports, parse_formats
from src.resolver.pipeline import Phase2InputError, load_phase1_file, resolve_from_phase1
from src.storage.sqlite_store import ScanDatabase
from src.utils.paths import (
    PHASE1_OUTPUT,
    PHASE2_OUTPUT,
    PHASE3_OUTPUT,
    domain_output_dir,
    dump_json,
    ensure_dirs,
    load_settings,
)
from src.utils.platform import attach_parent_console, run_async

console = Console()

SCOPE_WARNING = """\
[bold yellow]AUTHORIZED USE ONLY[/]
Only scan domains you own or have written permission to test
(bug-bounty scope / authorized pentest / lab targets).
This tool [bold]detects and reports only[/] — it never claims third-party
resources or exploits any finding."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subtake",
        description="Subdomain takeover & asset discovery tool (detect & report only).",
    )
    parser.add_argument(
        "--settings",
        type=Path,
        default=None,
        help="Alternative settings YAML (default: config/settings.yaml)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("discover", help="Phase 1: subdomain enumeration")
    p.add_argument("--domain", required=True, help="Target domain, e.g. example.com")
    p.add_argument(
        "--wordlist",
        type=Path,
        default=None,
        help="Brute-force wordlist (default: data/wordlists/subdomains.txt)",
    )
    p.add_argument(
        "--skip-brute", action="store_true", help="Skip the active wordlist brute-force"
    )
    p.add_argument(
        "--threads", type=int, default=None, help="Concurrency override (default: 100)"
    )
    p.add_argument(
        "--resolvers",
        nargs="+",
        default=None,
        help="DNS resolver override, e.g. --resolvers 1.1.1.1 8.8.8.8",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON (default: data/output/phase1_subdomains.json)",
    )

    p = sub.add_parser("resolve", help="Phase 2: DNS resolution & HTTP probing")
    p.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Phase 1 JSON (default: data/output/phase1_subdomains.json)",
    )
    p.add_argument(
        "--threads", type=int, default=None, help="Concurrency override (default: 100)"
    )
    p.add_argument(
        "--resolvers",
        nargs="+",
        default=None,
        help="DNS resolver override, e.g. --resolvers 1.1.1.1 8.8.8.8",
    )
    p.add_argument(
        "--rate",
        type=float,
        default=None,
        help="Max HTTP requests per second (default: unlimited)",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON (default: data/output/phase2_resolved.json)",
    )

    p = sub.add_parser("detect", help="Phase 3: takeover detection & verification")
    p.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Phase 2 JSON (default: data/output/phase2_resolved.json)",
    )
    p.add_argument(
        "--fingerprints",
        type=Path,
        default=None,
        help="Fingerprints YAML (default: config/fingerprints.yaml)",
    )
    p.add_argument(
        "--no-recheck",
        action="store_true",
        help="Disable the second live DNS re-check for dangling candidates",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON (default: data/output/phase3_findings.json)",
    )

    sub.add_parser(
        "gui",
        help="Open the point-and-click GUI (same pipeline, no terminal skills needed)",
    )

    p = sub.add_parser("scan", help="Full pipeline: discover → resolve → detect → reports")
    p.add_argument("--domain", required=True, help="Target domain, e.g. example.com")
    p.add_argument("--threads", type=int, default=None, help="Concurrency override (default: 100)")
    p.add_argument(
        "--timeout", type=float, default=None, help="Network timeout override in seconds"
    )
    p.add_argument(
        "--resolvers",
        nargs="+",
        default=None,
        help="DNS resolver override, e.g. --resolvers 1.1.1.1 8.8.8.8",
    )
    p.add_argument("--skip-brute", action="store_true", help="Skip the wordlist brute-force")
    p.add_argument(
        "--wordlist", type=Path, default=None, help="Custom brute-force wordlist"
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for phase files + reports (default: data/output)",
    )
    p.add_argument(
        "--format",
        default="html",
        help="Report formats: all | comma list of excel,csv,markdown,html,json (default: html)",
    )

    p = sub.add_parser(
        "clean",
        help="Delete stored scan records for a domain (SQLite; optionally its files)",
    )
    p.add_argument(
        "--domain",
        required=True,
        help="Domain whose stored records should be deleted",
    )
    p.add_argument(
        "--db",
        type=Path,
        default=None,
        help="SQLite file (default: data/output/<domain>/subtake.db)",
    )
    p.add_argument(
        "--purge-files",
        action="store_true",
        help="Also delete the domain's default results folder",
    )
    p.add_argument(
        "--source",
        choices=["cli", "gui"],
        default="cli",
        help="Results area to target (default folder: data/results/<source>/<domain>/)",
    )
    p.add_argument("--yes", action="store_true", help="Skip the confirmation prompts")
    return parser


def _db_save(db, scan_id, phase: str, result) -> None:
    """Best-effort phase write into SQLite — never let the DB kill a scan."""
    if db is None or scan_id is None:
        return
    try:
        savers = {
            "phase1": db.save_phase1,
            "phase2": db.save_phase2,
            "phase3": db.save_phase3,
        }
        savers[phase](scan_id, result)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]SQLite {phase} save failed: {exc}[/]")


def _persist_phase(out_path: Path, phase: str, result) -> None:
    """SQLite persistence for single-phase commands (Student Guide Phase 4)."""
    db_path = out_path.parent / "subtake.db"
    try:
        db = ScanDatabase(db_path)
        scan_id = db.new_scan(result.target)
        _db_save(db, scan_id, phase, result)
        db.close()
        console.print(f"[dim]SQLite database:[/] {db_path}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]SQLite unavailable — continuing without DB: {exc}[/]")


def cmd_discover(args: argparse.Namespace) -> int:
    """Phase 1 entry point: enumerate subdomains and write the contract file."""
    console.print(
        Panel(SCOPE_WARNING, title="Scope & Authorization", border_style="yellow")
    )
    try:
        domain = normalize_domain(args.domain)
    except InvalidDomainError as exc:
        console.print(f"[bold red]Invalid target:[/] {exc}")
        return 2

    settings = load_settings(args.settings)
    general = settings.setdefault("general", {})
    if args.threads:
        general["concurrency"] = args.threads
    if args.resolvers:
        general["resolvers"] = args.resolvers

    console.print(f"[bold cyan]Target:[/] {domain}")
    with console.status("[cyan]Enumerating subdomains…[/]"):
        result = run_async(
            enumerate_subdomains(
                domain, settings, skip_brute=args.skip_brute, wordlist=args.wordlist
            )
        )

    out_path = args.output if args.output is not None else PHASE1_OUTPUT
    ensure_dirs()
    dump_json(result.to_dict(), out_path)

    counts: dict[str, int] = {}
    for entry in result.subdomains:
        for source in entry.sources:
            counts[source] = counts.get(source, 0) + 1
    table = Table(title=f"Phase 1 complete — {len(result.subdomains)} unique subdomains")
    table.add_column("Source", style="cyan")
    table.add_column("Names found", justify="right")
    for source in result.sources_used:
        table.add_row(source, str(counts.get(source, 0)))
    console.print(table)
    console.print(f"[bold green]Saved:[/] {out_path}")
    _persist_phase(out_path, "phase1", result)
    return 0


def cmd_resolve(args: argparse.Namespace) -> int:
    """Phase 2 entry point: resolve Phase 1 subdomains + HTTP probe."""
    console.print(
        Panel(SCOPE_WARNING, title="Scope & Authorization", border_style="yellow")
    )
    settings = load_settings(args.settings)
    input_path = args.input if args.input is not None else PHASE1_OUTPUT

    try:
        total = len(load_phase1_file(input_path).subdomains)
    except Phase2InputError as exc:
        console.print(f"[bold red]Input error:[/] {exc}")
        return 2

    progress = Progress(
        TextColumn("[cyan]Resolving[/]"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    )
    with progress:
        task_id = progress.add_task("resolve", total=total)
        result = run_async(
            resolve_from_phase1(
                input_path,
                settings,
                threads=args.threads,
                resolvers=args.resolvers,
                rate=args.rate,
                progress_callback=lambda n: progress.update(task_id, completed=n),
            )
        )

    out_path = args.output if args.output is not None else PHASE2_OUTPUT
    ensure_dirs()
    dump_json(result.to_dict(), out_path)

    status_counts: dict[str, int] = {}
    http_ok = http_failed = 0
    for record in result.records:
        status_counts[record.dns_status] = status_counts.get(record.dns_status, 0) + 1
        if record.http.status is not None:
            http_ok += 1
        elif record.http.error:
            http_failed += 1
    table = Table(title=f"Phase 2 complete — {len(result.records)} records")
    table.add_column("DNS status", style="cyan")
    table.add_column("Count", justify="right")
    for status in ("NOERROR", "NXDOMAIN", "NODATA", "SERVFAIL", "TIMEOUT"):
        if status_counts.get(status):
            table.add_row(status, str(status_counts[status]))
    console.print(table)
    console.print(
        f"HTTP answered: [green]{http_ok}[/]   HTTP failed: [red]{http_failed}[/]"
    )
    console.print(f"[bold green]Saved:[/] {out_path}")
    _persist_phase(out_path, "phase2", result)
    return 0


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "white",
}


def cmd_detect(args: argparse.Namespace) -> int:
    """Phase 3 entry point: run detectors over Phase 2 records."""
    console.print(
        Panel(SCOPE_WARNING, title="Scope & Authorization", border_style="yellow")
    )
    settings = load_settings(args.settings)
    input_path = args.input if args.input is not None else PHASE2_OUTPUT

    try:
        total = len(load_phase2_file(input_path).records)
    except Phase3InputError as exc:
        console.print(f"[bold red]Input error:[/] {exc}")
        return 2

    with console.status("[cyan]Analyzing records…[/]"):
        result = run_detection(
            input_path,
            settings,
            fingerprints_path=args.fingerprints,
            recheck_dns=not args.no_recheck,
        )

    out_path = args.output if args.output is not None else PHASE3_OUTPUT
    ensure_dirs()
    dump_json(result.to_dict(), out_path)

    findings = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    if not findings:
        console.print(
            f"[bold green]No takeover findings across {total} record(s).[/]"
        )
    else:
        table = Table(title=f"Phase 3 — {len(findings)} finding(s) from {total} records")
        table.add_column("Severity", style="bold")
        table.add_column("Confidence", justify="center")
        table.add_column("Type", style="cyan")
        table.add_column("Subdomain")
        table.add_column("Service")
        for finding in findings:
            table.add_row(
                f"[{SEVERITY_STYLES.get(finding.severity, 'white')}]{finding.severity}[/]",
                finding.confidence,
                finding.type,
                finding.subdomain,
                finding.service,
            )
        console.print(table)
        console.print(
            "[dim]Findings are advisory. Verify manually before any action — "
            "this tool never claims or exploits anything.[/]"
        )
    summary = result.summary
    console.print(
        f"Scanned: {summary.get('total_scanned', 0)}   "
        f"Vulnerable (HIGH): [red]{summary.get('vulnerable', 0)}[/]   "
        f"MEDIUM: {summary.get('by_confidence', {}).get('MEDIUM', 0)}   "
        f"LOW: {summary.get('by_confidence', {}).get('LOW', 0)}"
    )
    console.print(f"[bold green]Saved:[/] {out_path}")
    _persist_phase(out_path, "phase3", result)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Unified entry point: run phases 1→3 on one domain, then build reports."""
    console.print(
        Panel(SCOPE_WARNING, title="Scope & Authorization", border_style="yellow")
    )
    try:
        domain = normalize_domain(args.domain)
    except InvalidDomainError as exc:
        console.print(f"[bold red]Invalid target:[/] {exc}")
        return 2

    formats = parse_formats(args.format)
    if formats is None:
        console.print(
            f"[bold red]Invalid --format:[/] use 'all' or a comma list of "
            f"json,csv,markdown,html (got {args.format!r})"
        )
        return 2

    settings = load_settings(args.settings)
    general = settings.setdefault("general", {})
    if args.threads:
        general["concurrency"] = args.threads
    if args.timeout:
        general["timeout"] = args.timeout
    if args.resolvers:
        general["resolvers"] = args.resolvers

    # Default: a dedicated per-domain results folder (data/output/<domain>/).
    out_dir = args.output_dir if args.output_dir is not None else domain_output_dir(domain)
    out_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[dim]Results folder:[/] {out_dir}")
    phase1_path = out_dir / "phase1_subdomains.json"
    phase2_path = out_dir / "phase2_resolved.json"
    phase3_path = out_dir / "phase3_findings.json"

    db = None
    scan_id = None
    try:
        db = ScanDatabase(out_dir / "subtake.db")
        scan_id = db.new_scan(domain)
    except Exception as exc:  # noqa: BLE001 — DB failure must not kill the scan
        console.print(f"[yellow]SQLite unavailable — continuing without DB: {exc}[/]")

    # ── Phase 1: subdomain enumeration ────────────────────────────────────
    console.print("[bold cyan]── Phase 1/3: subdomain enumeration[/]")
    try:
        with console.status("[cyan]Enumerating subdomains…[/]"):
            phase1 = run_async(
                enumerate_subdomains(
                    domain,
                    settings,
                    skip_brute=args.skip_brute,
                    wordlist=args.wordlist,
                )
            )
    except Exception as exc:  # noqa: BLE001 — surface, never traceback-dump
        console.print(f"[bold red]Phase 1 failed:[/] {exc}")
        return 1
    dump_json(phase1.to_dict(), phase1_path)
    _db_save(db, scan_id, "phase1", phase1)
    console.print(f"  Found [bold]{len(phase1.subdomains)}[/] unique subdomains → {phase1_path}")

    # ── Phase 2: DNS resolution & HTTP probing ────────────────────────────
    console.print("[bold cyan]── Phase 2/3: DNS resolution & HTTP probing[/]")
    try:
        with console.status("[cyan]Resolving and probing…[/]"):
            phase2 = run_async(
                resolve_from_phase1(
                    phase1_path, settings, threads=args.threads
                )
            )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Phase 2 failed:[/] {exc}")
        return 1
    dump_json(phase2.to_dict(), phase2_path)
    _db_save(db, scan_id, "phase2", phase2)
    resolved_count = sum(1 for record in phase2.records if record.resolved)
    console.print(
        f"  [bold]{resolved_count}[/]/{len(phase2.records)} records resolved → {phase2_path}"
    )

    # ── Phase 3: takeover detection ───────────────────────────────────────
    console.print("[bold cyan]── Phase 3/3: takeover detection[/]")
    try:
        with console.status("[cyan]Analyzing…[/]"):
            phase3 = run_detection(phase2_path, settings)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Phase 3 failed:[/] {exc}")
        return 1
    dump_json(phase3.to_dict(), phase3_path)
    _db_save(db, scan_id, "phase3", phase3)
    console.print(f"  [bold]{len(phase3.findings)}[/] finding(s) → {phase3_path}")

    # ── Reports ───────────────────────────────────────────────────────────
    console.print("[bold cyan]── Reports[/]")
    report_paths = generate_reports(phase3, out_dir, formats, phase1=phase1)
    for fmt, path in report_paths.items():
        console.print(f"  [green]{fmt}[/] → {path}")

    findings = sorted(phase3.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    if not findings:
        console.print("[bold green]Result: no takeover findings.[/]")
    else:
        table = Table(title=f"Scan summary — {len(findings)} finding(s)")
        table.add_column("Severity", style="bold")
        table.add_column("Confidence", justify="center")
        table.add_column("Type", style="cyan")
        table.add_column("Subdomain")
        table.add_column("Service")
        for finding in findings:
            table.add_row(
                f"[{SEVERITY_STYLES.get(finding.severity, 'white')}]{finding.severity}[/]",
                finding.confidence,
                finding.type,
                finding.subdomain,
                finding.service,
            )
        console.print(table)
        console.print(
            "[dim]Findings are advisory. Verify manually before any action — "
            "this tool never claims or exploits anything.[/]"
        )
    if db is not None:
        db.close()
        console.print(f"[dim]SQLite database:[/] {out_dir / 'subtake.db'}")
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    """Delete stored scan records for a domain — destructive, so confirmed."""
    console.print(
        Panel(
            "[bold red]DATA DELETION[/]\nThis permanently removes stored scan "
            "records (and with --purge-files, the results folder). "
            "Deleted rows cannot be recovered.",
            title="Clean stored results",
            border_style="red",
        )
    )
    try:
        domain = normalize_domain(args.domain)
    except InvalidDomainError as exc:
        console.print(f"[bold red]Invalid domain:[/] {exc}")
        return 2

    if args.db is not None:
        db_path = args.db
    else:
        db_path = domain_output_dir(domain, args.source) / "subtake.db"
    if not db_path.is_file():
        console.print(f"[yellow]No stored records found:[/] {db_path}")
        return 0

    try:
        db = ScanDatabase(db_path)
        counts = db.count_domain_records(domain)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Cannot open {db_path}:[/] {exc}")
        return 1

    if counts["scans"] == 0:
        console.print(f"[yellow]No records for {domain} in {db_path}.[/]")
        db.close()
        return 0
    console.print(
        f"Domain [cyan]{domain}[/] in {db_path}: "
        f"{counts['scans']} scan(s), {counts['subdomains']} subdomain row(s), "
        f"{counts['dns_records']} DNS record(s), {counts['findings']} finding(s)."
    )

    if not args.yes:
        if not sys.stdin.isatty():
            console.print(
                "[red]Non-interactive session — refusing to delete without --yes.[/]"
            )
            db.close()
            return 1
        if not Confirm.ask("Delete these records?", default=False):
            console.print("Cancelled — nothing was deleted.")
            db.close()
            return 0

    try:
        removed = db.delete_domain_records(domain)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Delete failed:[/] {exc}")
        db.close()
        return 1
    db.close()
    console.print(
        f"[green]Deleted:[/] {removed['scans']} scan(s), "
        f"{removed['subdomains']} subdomain row(s), "
        f"{removed['dns_records']} DNS record(s), {removed['findings']} finding(s)."
    )

    if args.purge_files:
        folder = domain_output_dir(domain, args.source)
        if not folder.is_dir():
            console.print(f"[yellow]No results folder at {folder}.[/]")
            return 0
        if not args.yes:
            if not sys.stdin.isatty() or not Confirm.ask(
                f"Also delete the results folder {folder}?", default=False
            ):
                console.print("[yellow]Folder kept.[/]")
                return 0
        shutil.rmtree(folder)
        console.print(f"[green]Folder deleted:[/] {folder}")
    return 0


def cmd_gui(_args: argparse.Namespace) -> int:
    """Launch the point-and-click GUI (same pipeline as the CLI commands)."""
    from src.gui import main as gui_main

    return gui_main()


HANDLERS = {
    "discover": cmd_discover,
    "resolve": cmd_resolve,
    "detect": cmd_detect,
    "scan": cmd_scan,
    "clean": cmd_clean,
    "gui": cmd_gui,
}


def _make_streams_utf8() -> None:
    """Force UTF-8 on stdout/stderr.

    Console pipes on localized Windows can fall back to legacy code pages
    (e.g. cp1256), which cannot encode characters like "→" used in help text
    — this surfaced in the PyInstaller build. errors="replace" keeps output
    flowing even on exotic consoles.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):  # pragma: no cover — exotic stream objects
            pass


#: SUBTAKE word-mark rendered in ANSI-shadow block letters, row by row.
#: The first three glyphs ("SUB") print silver, "TAKE" prints bright blue —
#: mirroring the brand logo (assets/logo.png).
_BANNER_GLYPHS = (
    ("███████╗", "██  ████╗", "██████╗ ", "████████╗", " █████╗ ", "██  ███╗", "███████╗"),
    ("██╔════╝", "██  ████║", "██╔══██╗", "╚══██╔══╝", "██╔══██╗", "██ ██╔╝ ", "██╔════╝"),
    ("███████╗", "██  ████║", "██████╔╝", "   ██║   ", "███████║", "█████╔╝ ", "█████╗  "),
    ("╚════██║", "██  ████║", "██╔══██╗", "   ██║   ", "██╔══██║", "██╔═██╗ ", "██╔══╝  "),
    ("███████║", "╚██████╔╝", "██████╔╝", "   ╚═╝   ", "╚═╝  ██║", "██║  ██╗", "███████╗"),
)


def print_banner() -> None:
    """Render the SUBTAKE word-mark + tagline when the tool is invoked."""
    from rich.align import Align
    from rich.console import Group
    from rich.text import Text

    rows = []
    for silver_a, silver_b, silver_c, blue_a, blue_b, blue_c, blue_d in _BANNER_GLYPHS:
        row = f"{silver_a} {silver_b} {silver_c}  {blue_a} {blue_b} {blue_c} {blue_d}"
        split = len(silver_a) + 1 + len(silver_b) + 1 + len(silver_c) + 2
        text = Text(row)
        text.stylize("bold #e2e8f0", 0, split)
        text.stylize("bold #38bdf8", split, len(row))
        rows.append(text)
    subtitle = Text(
        f"Subdomain-Takeover & Asset-Discovery Tool — v{__version__}",
        style="grey58",
        justify="center",
    )
    tagline = Text("DISCOVER   │   ANALYZE   │   SECURE", style="#38bdf8", justify="center")
    banner = Group(*rows, Text(""), subtitle, Text(""), tagline)
    console.print(Align.center(banner))
    console.print()


def main(argv: list[str] | None = None) -> int:
    attach_parent_console()  # windowed exe launched from a terminal keeps its output
    _make_streams_utf8()
    if argv is None and len(sys.argv) <= 1:
        # Bare `subtake` (e.g. double-clicking the installed program) opens the GUI.
        from src.gui import main as gui_main

        return gui_main()
    print_banner()
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )
    try:
        return HANDLERS[args.command](args)
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
