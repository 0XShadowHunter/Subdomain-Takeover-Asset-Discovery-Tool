"""Report generation from a Phase3Result: JSON / CSV / Markdown / HTML.

All reports are sorted by severity and open correctly on Windows and Linux
(UTF-8 everywhere; CSV uses utf-8-sig so Excel renders it cleanly). The HTML
report is a self-contained Jinja2 render — inline CSS only, no JS, no CDN.
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src import __version__
from src.models import Phase1Result, Phase3Result

log = logging.getLogger(__name__)

VALID_FORMATS = ("json", "csv", "markdown", "html", "excel")
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def parse_formats(raw: str | None) -> set[str] | None:
    """Parse ``--format``: 'all' or a comma-separated subset of VALID_FORMATS.

    Returns None when the input is invalid (caller prints the error).
    """
    if raw is None or raw.strip().lower() == "all":
        return set(VALID_FORMATS)
    formats = {part.strip().lower() for part in raw.split(",") if part.strip()}
    unknown = formats - set(VALID_FORMATS)
    if not formats or unknown:
        log.warning(
            "Unknown report format(s): %s — valid: all, %s",
            ", ".join(sorted(unknown)) or "(empty)",
            ", ".join(VALID_FORMATS),
        )
        return None
    return formats


def _sorted_findings(result: Phase3Result):
    return sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))


def _ordered_severity_counts(result: Phase3Result) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in _sorted_findings(result):
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _write_json(result: Phase3Result, path: Path) -> None:
    path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _write_csv(result: Phase3Result, path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:  # BOM → Excel-safe
        writer = csv.writer(fh)
        writer.writerow(
            [
                "severity",
                "confidence",
                "type",
                "subdomain",
                "service",
                "cname_target",
                "evidence",
                "remediation",
                "references",
            ]
        )
        for finding in _sorted_findings(result):
            writer.writerow(
                [
                    finding.severity,
                    finding.confidence,
                    finding.type,
                    finding.subdomain,
                    finding.service,
                    finding.cname_target or "",
                    finding.evidence,
                    finding.remediation,
                    " | ".join(finding.references),
                ]
            )


def _write_markdown(result: Phase3Result, path: Path) -> None:
    findings = _sorted_findings(result)
    by_confidence = result.summary.get("by_confidence", {})

    def esc(text: str | None) -> str:
        # Keep markdown tables intact even with pipes/newlines in evidence.
        return (text or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")

    lines: list[str] = [
        f"# Subdomain Takeover Report — {result.target}",
        "",
        f"- **Generated:** {result.generated_at}",
        f"- **Tool:** subtake v{__version__} (detect & report only)",
        "",
        "> ⚠️ **Advisory output.** Verify every finding manually before acting — "
        "this tool never claims, registers, or exploits anything.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Records scanned | {result.summary.get('total_scanned', 0)} |",
        f"| Vulnerable (HIGH confidence) | {result.summary.get('vulnerable', 0)} |",
        f"| MEDIUM confidence | {by_confidence.get('MEDIUM', 0)} |",
        f"| LOW confidence | {by_confidence.get('LOW', 0)} |",
        "",
    ]
    if not findings:
        lines += ["## Findings", "", "No takeover findings. 🎉", ""]
    else:
        lines += [
            f"## Findings ({len(findings)})",
            "",
            "| Severity | Confidence | Type | Subdomain | Service |",
            "|---|---|---|---|---|",
        ]
        for finding in findings:
            lines.append(
                f"| **{finding.severity}** | {finding.confidence} | {finding.type} "
                f"| {esc(finding.subdomain)} | {esc(finding.service)} |"
            )
        lines += ["", "### Details", ""]
        for finding in findings:
            lines.append(
                f"#### [{finding.severity}] {esc(finding.subdomain)} — "
                f"{finding.type} ({finding.confidence})"
            )
            lines.append("")
            lines.append(f"- **Service:** {esc(finding.service)}")
            if finding.cname_target:
                lines.append(f"- **CNAME target:** {esc(finding.cname_target)}")
            lines.append(f"- **Evidence:** {esc(finding.evidence)}")
            lines.append(f"- **Remediation:** {esc(finding.remediation)}")
            if finding.references:
                lines.append("- **References:** " + " · ".join(finding.references))
            lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_html(
    result: Phase3Result, path: Path, phase1: Phase1Result | None = None
) -> None:
    environment = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(["html"]),
    )
    template = environment.get_template("report.html.j2")
    html = template.render(
        target=result.target,
        generated_at=result.generated_at,
        version=__version__,
        findings=[finding.to_dict() for finding in _sorted_findings(result)],
        summary=result.summary,
        severity_counts=_ordered_severity_counts(result),
        subdomains=(
            [
                {
                    "name": entry.name,
                    "sources": ", ".join(entry.sources),
                }
                for entry in phase1.subdomains
            ]
            if phase1 is not None
            else None
        ),
    )
    path.write_text(html, encoding="utf-8")


def _write_excel(
    result: Phase3Result,
    path: Path,
    phase1: Phase1Result | None = None,
) -> None:
    """Multi-sheet workbook: Summary / Subdomains / Findings (severity-colored).

    ``openpyxl`` is imported lazily so the rest of the reporting module works
    without it.
    """
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    header_fill = PatternFill("solid", fgColor="1F6FB2")
    header_font = Font(bold=True, color="FFFFFF")
    severity_fills = {
        "CRITICAL": PatternFill("solid", fgColor="B91C1C"),
        "HIGH": PatternFill("solid", fgColor="F87171"),
        "MEDIUM": PatternFill("solid", fgColor="FBBF24"),
        "LOW": PatternFill("solid", fgColor="22D3EE"),
        "INFO": PatternFill("solid", fgColor="94A3B8"),
    }

    def _style_header(sheet, columns: int, row: int = 1) -> None:
        for col in range(1, columns + 1):
            cell = sheet.cell(row=row, column=col)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="left")

    def _auto_width(sheet, widths: dict[int, int]) -> None:
        for col, width in widths.items():
            sheet.column_dimensions[get_column_letter(col)].width = width

    workbook = Workbook()

    # ── Summary ──────────────────────────────────────────────────────────
    summary = workbook.active
    summary.title = "Summary"
    summary.append(["Subdomain Takeover Report", result.target])
    summary.append(["Generated", result.generated_at])
    summary.append(["Tool", f"subtake v{__version__} (detect & report only)"])
    summary.append([])
    summary.append(["Metric", "Value"])
    _style_header(summary, 2, row=5)
    summary.append(["Records scanned", result.summary.get("total_scanned", 0)])
    summary.append(["Vulnerable (HIGH confidence)", result.summary.get("vulnerable", 0)])
    for level in ("MEDIUM", "LOW"):
        summary.append(
            [
                f"{level} confidence",
                result.summary.get("by_confidence", {}).get(level, 0),
            ]
        )
    _auto_width(summary, {1: 30, 2: 46})

    # ── Subdomains (from the Phase 1 contract, when provided) ────────────
    if phase1 is not None:
        subdomains = workbook.create_sheet("Subdomains")
        subdomains.append(["Target Domain", "Subdomain", "Sources"])
        _style_header(subdomains, 3)
        for entry in phase1.subdomains:
            subdomains.append(
                [phase1.target, entry.name, ", ".join(entry.sources)]
            )
        _auto_width(subdomains, {1: 24, 2: 36, 3: 26})
        subdomains.freeze_panes = "A2"
        subdomains.auto_filter.ref = filter_range(subdomains.max_row, 3)

    # ── Findings ─────────────────────────────────────────────────────────
    findings = workbook.create_sheet("Findings")
    findings.append(
        [
            "Severity",
            "Confidence",
            "Type",
            "Subdomain",
            "Service",
            "CNAME target",
            "Evidence",
            "Remediation",
            "References",
        ]
    )
    _style_header(findings, 9)
    for finding in _sorted_findings(result):
        row_index = findings.max_row + 1
        findings.append(
            [
                finding.severity,
                finding.confidence,
                finding.type,
                finding.subdomain,
                finding.service,
                finding.cname_target or "",
                finding.evidence,
                finding.remediation,
                " | ".join(finding.references),
            ]
        )
        fill = severity_fills.get(finding.severity)
        if fill is not None:
            findings.cell(row=row_index, column=1).fill = fill
    _auto_width(
        findings,
        {1: 12, 2: 12, 3: 20, 4: 28, 5: 18, 6: 24, 7: 46, 8: 46, 9: 40},
    )
    findings.freeze_panes = "A2"

    workbook.save(path)


def filter_range(last_row: int, columns: int) -> str:
    """AutoFilter range helper (kept as a function for clarity in tests)."""
    from openpyxl.utils import get_column_letter

    return f"A1:{get_column_letter(columns)}{last_row}"


_WRITERS = {
    "json": _write_json,
    "csv": _write_csv,
    "markdown": _write_markdown,
}


def generate_reports(
    result: Phase3Result,
    output_dir: Path,
    formats: set[str],
    phase1: Phase1Result | None = None,
) -> dict[str, Path]:
    """Write one ``report.<ext>`` per requested format; returns format → path.

    ``phase1`` is optional and feeds the "all discovered subdomains" sections
    of the Excel and HTML reports.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    extensions = {
        "json": "json",
        "csv": "csv",
        "markdown": "md",
        "html": "html",
        "excel": "xlsx",
    }
    paths: dict[str, Path] = {}
    for fmt in VALID_FORMATS:  # stable write order
        if fmt not in formats:
            continue
        path = output_dir / f"report.{extensions[fmt]}"
        if fmt == "excel":
            _write_excel(result, path, phase1)
        elif fmt == "html":
            _write_html(result, path, phase1)
        else:
            _WRITERS[fmt](result, path)
        paths[fmt] = path
        log.info("Wrote %s report: %s", fmt, path)
    return paths
