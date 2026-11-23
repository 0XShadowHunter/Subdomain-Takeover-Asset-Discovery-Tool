"""Open the real GUI and run a live scan on a target passed as argv[1].

The window appears on the user's screen (topmost) and the scan runs visibly.
Screenshots are captured (mid-scan + final) and a summary is printed BEFORE
the window is handed over to the user (mainloop keeps it open).

Run:  .venv\\Scripts\\python.exe -u scripts\\gui_demo.py amit-learning.com
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

SHOTS_DIR = Path(__file__).resolve().parent / "gui_selftest_shots"
SHOTS_DIR.mkdir(exist_ok=True)


def capture(root: tk.Tk, path: Path) -> None:
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


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python -u scripts/gui_demo.py <domain>")
        return 2
    domain = sys.argv[1]

    gui._enable_windows_dpi_awareness()  # noqa: SLF001
    root = tk.Tk()
    app = gui.SubtakeGUI(root)
    root.attributes("-topmost", True)
    root.update()

    app.domain_var.set(domain)
    app.threads_var.set("25")
    app.timeout_var.set("10")
    app.skip_brute_var.set(False)  # full scan: passive + brute-force
    out_dir = SHOTS_DIR / "amit_out"
    app.output_var.set(str(out_dir))

    t0 = time.time()
    app.start_button.invoke()

    deadline = time.time() + 540  # 9 minutes safety net
    mid_captured = False
    while time.time() < deadline:
        root.update()
        status = app.status_var.get().lower()
        elapsed = time.time() - t0
        if not mid_captured and elapsed > 6:
            capture(root, SHOTS_DIR / "amit_midscan.png")
            mid_captured = True
        if "finished" in status or "failed" in status:
            break
        time.sleep(0.05)

    root.update()
    capture(root, SHOTS_DIR / "amit_done.png")
    print(f"DOMAIN: {domain}")
    print(f"STATUS: {app.status_var.get()}")
    print(f"FINDING ROWS: {len(app.tree.get_children())}")
    print(f"SUMMARY: {app.summary_var.get()}")
    print(f"REPORTS WRITTEN: {(out_dir / 'report.html').is_file()} -> {out_dir}")
    print(f"ELAPSED: {time.time() - t0:.0f}s")

    # Hand the window over to the user (stays open until they close it).
    root.attributes("-topmost", False)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
