"""Automated interactive selftest for the GUI — drives the real window.

What it does:
  1. Opens the real GUI window (kept topmost so screenshots capture it).
  2. Screenshot #1 — startup state.
  3. Runs a MOCKED scan (deterministic findings: HIGH + MEDIUM + LOW) by
     temporarily replacing gui.run_scan_job → verifies UI wiring end-to-end
     (start button, live log, findings table, open-folder button) → screenshot #2.
  4. Runs a REAL scan against example.com (skip-brute, polite settings) →
     waits for completion → screenshot #3.
  5. Prints PASS/FAIL lines; exits non-zero on any failure.

Run:  .venv\\Scripts\\python.exe scripts\\gui_selftest.py
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import tkinter as tk  # noqa: E402

from src import gui  # noqa: E402
from src.models import Finding, Phase3Result  # noqa: E402

SHOTS_DIR = Path(__file__).resolve().parent / "gui_selftest_shots"
SHOTS_DIR.mkdir(exist_ok=True)

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def capture(root: tk.Tk, path: Path) -> None:
    """Screenshot exactly the window rect via PowerShell (no extra deps)."""
    root.update_idletasks()
    x, y = root.winfo_rootx(), root.winfo_rooty()
    w, h = root.winfo_width(), root.winfo_height()
    script = SHOTS_DIR / "_capture.ps1"
    script.write_text(
        "Add-Type -AssemblyName System.Drawing\n"
        "Add-Type -AssemblyName System.Windows.Forms\n"
        f"$b = New-Object System.Drawing.Bitmap {w}, {h}\n"
        "$g = [System.Drawing.Graphics]::FromImage($b)\n"
        f"$g.CopyFromScreen({x}, {y}, 0, 0, $b.Size)\n"
        f"$b.Save('{path.as_posix()}')\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        check=True,
        timeout=30,
    )


def wait_for_status(root: tk.Tk, needles: tuple[str, ...], timeout_s: float) -> bool:
    """Drive the Tk event loop until the status label contains one of needles."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        root.update()
        status = app.status_var.get().lower()
        if any(n in status for n in needles):
            return True
        time.sleep(0.05)
    return False


def fake_scan_job(job: dict, events: queue_like) -> None:  # noqa: ANN001 — duck-typed queue
    """Deterministic stand-in for run_scan_job with realistic findings."""
    time.sleep(1.0)  # let a mid-scan status be observable
    events.put(("log", "── Phase 1: subdomain enumeration (mocked)"))
    events.put(("log", "✔ Phase 1 done — 7 unique subdomains found"))
    events.put(("status", "Phase 2/3 — DNS resolution & HTTP probing…"))
    time.sleep(1.0)
    events.put(("log", "✔ Phase 2 done — 7/7 records resolved"))
    events.put(("log", "── Phase 3: takeover detection (mocked)"))
    result = Phase3Result(
        target="example.com",
        generated_at="2026-11-22T00:00:00+00:00",
        findings=[
            Finding(
                subdomain="blog.example.com",
                type="CNAME_FINGERPRINT",
                service="GitHub Pages",
                cname_target="blog.example.github.io",
                evidence="HTTP 404 matched fingerprint 'There isn't a GitHub Pages site here.'",
                confidence="HIGH",
                severity="HIGH",
                references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                remediation="Create the missing GitHub Pages site or remove the CNAME.",
            ),
            Finding(
                subdomain="lost.example.com",
                type="CNAME_NXDOMAIN",
                service="unknown",
                cname_target="dead.invalid",
                evidence="CNAME target confirmed NXDOMAIN by a second DNS query",
                confidence="MEDIUM",
                severity="HIGH",
                references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                remediation="Remove the dangling CNAME record.",
            ),
            Finding(
                subdomain="maybe.example.com",
                type="CNAME_FINGERPRINT",
                service="Pingdom (public status page)",
                evidence="edge-case fingerprint matched — manual review needed",
                confidence="MEDIUM",
                severity="LOW",
                references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                remediation="Verify manually.",
            ),
        ],
        summary={"total_scanned": 7, "vulnerable": 1,
                 "by_confidence": {"HIGH": 1, "MEDIUM": 2, "LOW": 0}},
    )
    events.put(("findings", result))
    events.put(("reports", str(job["out_dir"].resolve())))
    events.put(("done", "Scan finished — reports are ready."))


queue_like = type(__import__("queue").Queue())

if __name__ == "__main__":
    gui._enable_windows_dpi_awareness()  # noqa: SLF001 — selftest needs the real flow
    root = tk.Tk()
    app = gui.SubtakeGUI(root)
    root.attributes("-topmost", True)
    root.update()

    # ── 1) startup screenshot ────────────────────────────────────────────
    capture(root, SHOTS_DIR / "gui_1_startup.png")
    check("startup renders", bool(root.winfo_width() > 500))

    # ── 1.5) clipboard: paste/copy/cut in the target field ──────────────
    # Note: synthetic keyboard events (event_generate) never fire bindings in
    # this environment, so we verify (a) every shortcut IS wired, then
    # (b) the exact actions the handlers run on a real key press.
    entry = app.domain_entry
    for seq in ("<Control-v>", "<Control-c>", "<Control-x>", "<Control-a>", "<Button-3>"):
        check(f"clipboard binding wired {seq}", bool(entry.bind(seq)))

    root.clipboard_clear()
    root.clipboard_append("amit-learning.com")
    root.update()
    entry.delete(0, "end")
    gui._paste_text(entry)  # noqa: SLF001 — same call the Ctrl+V handler makes
    root.update()
    check(
        "paste into target field",
        app.domain_var.get() == "amit-learning.com",
        repr(app.domain_var.get()),
    )
    gui._select_all_text(entry)  # noqa: SLF001
    root.update()
    check("select all", bool(entry.selection_present()))
    root.clipboard_clear()
    root.clipboard_append("test.com")
    root.update()
    gui._paste_text(entry)  # noqa: SLF001 — must replace the selection
    root.update()
    check("paste replaces selection", app.domain_var.get() == "test.com")
    gui._select_all_text(entry)  # noqa: SLF001
    gui._cut_text(entry)  # noqa: SLF001
    root.update()
    check("cut clears field", app.domain_var.get() == "")
    try:
        check("cut copies to clipboard", root.clipboard_get() == "test.com")
    except Exception as exc:  # noqa: BLE001
        check("cut copies to clipboard", False, str(exc))
    entry.delete(0, "end")
    app.domain_var.set("example.com")  # reset for the mocked scan

    # ── 2) mocked scan: deterministic UI wiring test ────────────────────
    original_scan_job = gui.run_scan_job
    gui.run_scan_job = fake_scan_job
    app.domain_var.set("example.com")
    app.start_button.invoke()
    ok = wait_for_status(root, ("finished", "failed"), timeout_s=30)
    check("mocked scan completes", ok, app.status_var.get())
    check(
        "findings table populated",
        len(app.tree.get_children()) == 3,
        f"rows={len(app.tree.get_children())}",
    )
    check(
        "severity order highest-first",
        [app.tree.item(item)["values"][0] for item in app.tree.get_children()][:1] == ["HIGH"],
    )
    check(
        "open-folder button enabled after scan",
        app.open_button.instate(["!disabled"]),
    )
    capture(root, SHOTS_DIR / "gui_2_findings.png")
    gui.run_scan_job = original_scan_job

    # ── 3) REAL scan against example.com (polite: skip-brute) ───────────
    app.domain_var.set("example.com")
    app.threads_var.set("10")
    app.skip_brute_var.set(True)
    real_out = SHOTS_DIR / "real_out"
    app.output_var.set(str(real_out))
    app.start_button.invoke()
    ok = wait_for_status(root, ("finished", "failed"), timeout_s=240)
    check("real scan completes", ok, app.status_var.get())
    check(
        "real scan wrote reports",
        (real_out / "report.html").is_file(),
        str(real_out),
    )
    capture(root, SHOTS_DIR / "gui_3_real_done.png")

    root.destroy()

    print()
    print(f"Screenshots: {SHOTS_DIR}")
    if failures:
        print(f"SELFTEST RESULT: {len(failures)} FAILURE(S) → {failures}")
        sys.exit(1)
    print("SELFTEST RESULT: ALL PASS")
