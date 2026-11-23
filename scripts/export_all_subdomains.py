"""Aggregate EVERY discovered subdomain on disk into one Excel workbook.

Walks the project tree for phase1_subdomains.json files and subtake.db
databases (CLI area, GUI area, old flat layout, exe folder, selftest outputs),
merges and dedupes them, and writes:

    data/results/summary/all_subdomains.xlsx

Sheets:
  - All Subdomains : No | Target Domain | Subdomain | Sources | Last Scan
  - Per Domain     : unique-subdomain counts per target

Run:  .venv\\Scripts\\python.exe scripts\\export_all_subdomains.py
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from openpyxl import Workbook  # noqa: E402
from openpyxl.styles import Alignment, Font, PatternFill  # noqa: E402
from openpyxl.utils import get_column_letter  # noqa: E402

OUTPUT = ROOT / "data" / "results" / "summary" / "all_subdomains.xlsx"
HEADER_FILL = PatternFill("solid", fgColor="1F6FB2")


def _skip(path: Path) -> bool:
    text = str(path).replace("\\", "/").lower()
    return ".venv/" in text or "_mei" in text or "/build/" in text


def _merge_key(target: str, subdomain: str) -> tuple[str, str]:
    return target.lower(), subdomain.lower()


def _note(rows: dict, target: str, subdomain: str, source: str, seen_at: str) -> None:
    key = _merge_key(target, subdomain)
    if not key[1]:
        return
    bucket = rows.setdefault(key, {"sources": set(), "last": ""})
    if source:
        bucket["sources"].add(source)
    if seen_at > bucket["last"]:
        bucket["last"] = seen_at


def collect() -> tuple[dict, int]:
    rows: dict[tuple[str, str], dict] = {}
    files = 0

    for phase1 in ROOT.rglob("phase1_subdomains.json"):
        if _skip(phase1):
            continue
        try:
            data = json.loads(phase1.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 — unreadable files are skipped
            continue
        target = str(data.get("target", "")).lower()
        seen_at = str(data.get("generated_at", ""))
        if not target:
            continue
        files += 1
        for entry in data.get("subdomains", []):
            _note(
                rows,
                target,
                str(entry.get("name", "")),
                ",".join(str(s) for s in entry.get("sources", [])),
                seen_at,
            )

    for database in ROOT.rglob("subtake.db"):
        if _skip(database):
            continue
        try:
            connection = sqlite3.connect(str(database))
            try:
                cursor = connection.execute(
                    "SELECT sc.target, su.name, su.source, sc.started_at"
                    " FROM subdomains su JOIN scans sc ON sc.id = su.scan_id"
                )
                for target, name, source, seen_at in cursor.fetchall():
                    _note(rows, str(target), str(name), str(source), str(seen_at))
            finally:
                connection.close()
            files += 1
        except Exception:  # noqa: BLE001 — unreadable DBs are skipped
            continue

    return rows, files


def _style_header(sheet, columns: int) -> None:
    for col in range(1, columns + 1):
        cell = sheet.cell(row=1, column=col)
        cell.fill = HEADER_FILL
        cell.font = Font(bold=True, color="FFFFFF")
        cell.alignment = Alignment(horizontal="left")


def main() -> int:
    rows, files = collect()
    if not rows:
        print("No discovered subdomains found in any result file.")
        return 1

    targets = sorted({target for target, _ in rows})

    workbook = Workbook()

    # ── All Subdomains ───────────────────────────────────────────────────
    sheet = workbook.active
    sheet.title = "All Subdomains"
    sheet.append(["No", "Target Domain", "Subdomain", "Sources", "Last Scan"])
    _style_header(sheet, 5)
    for index, ((target, subdomain), bucket) in enumerate(
        sorted(rows.items(), key=lambda item: (item[0][0], item[0][1])), start=1
    ):
        sheet.append(
            [
                index,
                target,
                subdomain,
                ", ".join(sorted(bucket["sources"])),
                bucket["last"],
            ]
        )
    for col, width in {1: 6, 2: 24, 3: 36, 4: 28, 5: 30}.items():
        sheet.column_dimensions[get_column_letter(col)].width = width
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = f"A1:{get_column_letter(5)}{sheet.max_row}"

    # ── Per Domain ───────────────────────────────────────────────────────
    per_domain = workbook.create_sheet("Per Domain")
    per_domain.append(["Target Domain", "Unique Subdomains"])
    _style_header(per_domain, 2)
    for target in targets:
        count = sum(1 for key in rows if key[0] == target)
        per_domain.append([target, count])
    for col, width in {1: 28, 2: 20}.items():
        per_domain.column_dimensions[get_column_letter(col)].width = width
    per_domain.freeze_panes = "A2"

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(OUTPUT)

    print(f"Result files merged : {files}")
    print(f"Targets             : {len(targets)} ({', '.join(targets)})")
    print(f"Unique subdomains   : {len(rows)}")
    print(f"Saved               : {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
