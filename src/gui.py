"""Point-and-click GUI for users who don't live in a terminal.

Launch paths (all equivalent):
  - ``python -m src.gui``
  - ``subtake-gui``          (console script after ``pip install -e .``)
  - ``subtake``              (bare command / double-clicked exe → opens the GUI)
  - ``python -m src.cli gui``

Design notes:
  - tkinter only (stdlib) — zero extra dependencies, works on Windows/Linux,
    and bundles cleanly with PyInstaller.
  - Dark theme consistent with the HTML report branding; DPI-aware on Windows.
  - Layout: header + authorization strip + (scrollable form | results) + an
    always-visible footer toolbar (start / open / clear + live progress), so
    every action stays reachable on short screens.
  - The scan runs in a worker thread; the UI thread only drains a queue, so
    the window never freezes and the live log keeps streaming.
  - Same pipeline modules as the CLI — one code path, no duplicated logic.
"""

from __future__ import annotations

import ctypes
import logging
import os
import queue
import shutil
import subprocess
import sys
import threading
import tkinter.font as tkfont
from pathlib import Path

try:  # tkinter is stdlib but missing on some minimal Linux installs
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    TK_AVAILABLE = True
except Exception:  # noqa: BLE001 — headless environments
    TK_AVAILABLE = False
    tk = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    filedialog = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]

from src import __version__
from src.detection.pipeline import run_detection
from src.discovery.pipeline import enumerate_subdomains
from src.discovery.validators import InvalidDomainError, normalize_domain
from src.models import Finding, Phase3Result
from src.reporting.reports import VALID_FORMATS, generate_reports
from src.resolver.pipeline import resolve_from_phase1
from src.storage.sqlite_store import ScanDatabase
from src.utils.paths import (
    ICON_FILE,
    LOGO_FILE,
    RESULTS_DIR,
    domain_output_dir,
    dump_json,
    load_settings,
)
from src.utils.platform import IS_WINDOWS, run_async

#: Dark theme — kept in sync with the HTML report (report.html.j2) branding.
THEME = {
    "bg": "#0b1220",        # window background
    "card": "#111a2e",      # panel/card background
    "card2": "#16213a",     # slightly raised card
    "border": "#1f2b45",
    "text": "#e2e8f0",
    "muted": "#8fa1bb",
    "accent": "#38bdf8",
    "accent_dark": "#0ea5e9",
    "field": "#0f172a",
    "warn_bg": "#3b2f14",
    "warn_fg": "#fbbf24",
    "ok": "#22c55e",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#f87171",
    "MEDIUM": "#fbbf24",
    "LOW": "#22d3ee",
    "INFO": "#94a3b8",
}


def sort_findings_for_display(findings: list[Finding]) -> list[Finding]:
    """Severity-sorted findings for tables/reports (highest first)."""
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))


def build_job(
    domain_raw: str,
    threads_raw: str,
    timeout_raw: str,
    resolvers_raw: str,
    wordlist_raw: str,
    output_dir_raw: str,
    skip_brute: bool,
    formats_checked: list[str],
    settings: dict | None = None,
) -> dict:
    """Validate the form values and build the scan job dict.

    Pure function (no tkinter) so it is unit-testable; raises ``ValueError``
    with a user-friendly message on bad input.
    """
    try:
        domain = normalize_domain(domain_raw)
    except InvalidDomainError as exc:
        raise ValueError(str(exc)) from exc

    settings = settings if settings is not None else load_settings()
    general = settings.setdefault("general", {})

    try:
        threads = int(threads_raw) if str(threads_raw).strip() else None
    except ValueError as exc:
        raise ValueError(f"Threads must be a number, got {threads_raw!r}") from exc
    if threads:
        general["concurrency"] = threads

    try:
        timeout = float(timeout_raw) if str(timeout_raw).strip() else None
    except ValueError as exc:
        raise ValueError(f"Timeout must be a number, got {timeout_raw!r}") from exc
    if timeout:
        general["timeout"] = timeout

    resolvers = [r.strip() for r in str(resolvers_raw).split() if r.strip()]
    if resolvers:
        general["resolvers"] = resolvers

    formats = {f for f in formats_checked if f in VALID_FORMATS} or {"html"}
    out_dir = Path(output_dir_raw) if str(output_dir_raw).strip() else RESULTS_DIR / "gui"
    out_dir.mkdir(parents=True, exist_ok=True)

    return {
        "domain": domain,
        "settings": settings,
        "threads": threads,
        "skip_brute": bool(skip_brute),
        "wordlist": Path(wordlist_raw) if str(wordlist_raw).strip() else None,
        "out_dir": out_dir,
        "formats": formats,
        "phase1_path": out_dir / "phase1_subdomains.json",
        "phase2_path": out_dir / "phase2_resolved.json",
        "phase3_path": out_dir / "phase3_findings.json",
    }


class _QueueLogHandler(logging.Handler):
    """Forwards log records from the worker thread into the UI queue."""

    def __init__(self, events: queue.Queue):
        super().__init__(logging.INFO)
        self.events = events

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.events.put(("log", self.format(record)))
        except Exception:  # noqa: BLE001 — logging must never break the scan
            pass


def run_scan_job(job: dict, events: queue.Queue) -> None:
    """Worker-thread target: runs the full pipeline, streaming events to the UI.

    Event tuples: ("status", text) | ("log", line) | ("findings", Phase3Result)
    | ("reports", out_dir_str) | ("done", text) | ("error", text).
    """
    handler = _QueueLogHandler(events)
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s", "%H:%M:%S")
    )
    root = logging.getLogger()
    root.addHandler(handler)
    previous_level = root.level
    root.setLevel(logging.INFO)
    db = None
    scan_id = None
    try:
        db = ScanDatabase(job["out_dir"] / "subtake.db")
        scan_id = db.new_scan(job["domain"])
    except Exception as exc:  # noqa: BLE001 — DB must never kill the scan
        events.put(("log", f"SQLite unavailable — continuing without DB: {exc}"))
    try:
        events.put(("status", "Phase 1/3 — enumerating subdomains…"))
        events.put(("log", "── Phase 1: subdomain enumeration"))
        phase1 = run_async(
            enumerate_subdomains(
                job["domain"],
                job["settings"],
                skip_brute=job["skip_brute"],
                wordlist=job["wordlist"],
            )
        )
        dump_json(phase1.to_dict(), job["phase1_path"])
        if db is not None and scan_id is not None:
            try:
                db.save_phase1(scan_id, phase1)
            except Exception as exc:  # noqa: BLE001
                events.put(("log", f"SQLite phase1 save failed: {exc}"))
        events.put(
            ("log", f"✔ Phase 1 done — {len(phase1.subdomains)} unique subdomains found")
        )

        events.put(("status", "Phase 2/3 — DNS resolution & HTTP probing…"))
        events.put(("log", "── Phase 2: DNS resolution & HTTP probing"))
        phase2 = run_async(
            resolve_from_phase1(job["phase1_path"], job["settings"], threads=job["threads"])
        )
        dump_json(phase2.to_dict(), job["phase2_path"])
        if db is not None and scan_id is not None:
            try:
                db.save_phase2(scan_id, phase2)
            except Exception as exc:  # noqa: BLE001
                events.put(("log", f"SQLite phase2 save failed: {exc}"))
        resolved = sum(1 for record in phase2.records if record.resolved)
        events.put(
            ("log", f"✔ Phase 2 done — {resolved}/{len(phase2.records)} records resolved")
        )

        events.put(("status", "Phase 3/3 — takeover detection…"))
        events.put(("log", "── Phase 3: takeover detection"))
        phase3 = run_detection(job["phase2_path"], job["settings"])
        dump_json(phase3.to_dict(), job["phase3_path"])
        if db is not None and scan_id is not None:
            try:
                db.save_phase3(scan_id, phase3)
            except Exception as exc:  # noqa: BLE001
                events.put(("log", f"SQLite phase3 save failed: {exc}"))
        events.put(("log", f"✔ Phase 3 done — {len(phase3.findings)} finding(s)"))

        events.put(("status", "Generating reports…"))
        events.put(("log", "── Reports"))
        generate_reports(phase3, job["out_dir"], job["formats"], phase1=phase1)
        events.put(("reports", str(job["out_dir"].resolve())))
        events.put(("findings", phase3))
        events.put(("done", "Scan finished — reports are ready."))
    except Exception as exc:  # noqa: BLE001 — surfaced to the UI, never crash silently
        events.put(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:  # noqa: BLE001
                pass
        root.removeHandler(handler)
        root.setLevel(previous_level)


def _open_folder(path: Path) -> None:
    """Open a folder in the OS file manager (Windows/macOS/Linux)."""
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # noqa: S606 — intended user action
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except OSError as exc:
        messagebox.showerror("Open folder", str(exc))


def _selected_text(entry) -> str:
    """Return the currently selected text of an Entry ('' when nothing)."""
    try:
        if entry.selection_present():
            return entry.get(entry.index("sel.first"), entry.index("sel.last"))
    except Exception:  # noqa: BLE001 — no selection
        pass
    return ""


def _paste_text(entry) -> None:
    """Insert the clipboard content at the cursor (replacing any selection).

    Implemented directly via clipboard_get() instead of Tk's <<Paste>> virtual
    event — the virtual-event route is unreliable on localized Windows setups.
    """
    try:
        text = entry.clipboard_get()
    except Exception:  # noqa: BLE001 — empty clipboard
        return
    try:
        if entry.selection_present():
            entry.delete("sel.first", "sel.last")
        position = entry.index("insert")
        entry.insert(position, text)
        entry.icursor(position + len(text))
    except Exception:  # noqa: BLE001
        pass


def _copy_text(entry) -> None:
    """Copy the selected text into the OS clipboard."""
    text = _selected_text(entry)
    if text:
        entry.clipboard_clear()
        entry.clipboard_append(text)


def _cut_text(entry) -> None:
    """Copy the selection, then remove it."""
    _copy_text(entry)
    try:
        if entry.selection_present():
            entry.delete("sel.first", "sel.last")
    except Exception:  # noqa: BLE001
        pass


def _select_all_text(entry) -> None:
    entry.select_range(0, "end")
    entry.icursor("end")


def attach_clipboard_menu(entry) -> None:
    """Guarantee Cut/Copy/Paste/Select-All works on an Entry widget.

    Tk entries ship without a right-click context menu, and on localized
    Windows setups the default Ctrl+V binding can be missed — so we implement
    the clipboard operations directly and add the menu users expect.
    """
    menu = tk.Menu(
        entry,
        tearoff=0,
        bg=THEME["card"],
        fg=THEME["text"],
        activebackground=THEME["accent_dark"],
        activeforeground="#06121f",
        font=("Segoe UI", 9),
        bd=1,
        relief="solid",
    )
    menu.add_command(label="Cut", command=lambda: _cut_text(entry))
    menu.add_command(label="Copy", command=lambda: _copy_text(entry))
    menu.add_command(label="Paste", command=lambda: _paste_text(entry))
    menu.add_separator()
    menu.add_command(label="Select All", command=lambda: _select_all_text(entry))

    def _popup(event) -> str:
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return "break"

    def _handler(action):
        def handler(_event) -> str:
            action()
            return "break"  # stop the (possibly broken) default binding

        return handler

    entry.bind("<Button-3>", _popup)  # right-click → Cut/Copy/Paste menu
    entry.bind("<Control-x>", _handler(lambda: _cut_text(entry)))
    entry.bind("<Control-X>", _handler(lambda: _cut_text(entry)))
    entry.bind("<Control-c>", _handler(lambda: _copy_text(entry)))
    entry.bind("<Control-C>", _handler(lambda: _copy_text(entry)))
    entry.bind("<Control-v>", _handler(lambda: _paste_text(entry)))
    entry.bind("<Control-V>", _handler(lambda: _paste_text(entry)))
    entry.bind("<Control-a>", _handler(_select_all_text))
    entry.bind("<Control-A>", _handler(_select_all_text))


def _enable_windows_dpi_awareness() -> None:
    """Crisp rendering on high-DPI Windows displays (no-op elsewhere)."""
    if not IS_WINDOWS:
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001 — older Windows versions
        pass


def load_logo_image(width_target: int = 72) -> tk.PhotoImage | None:
    """Load the brand logo downscaled to ~``width_target`` px; None when absent.

    Tk's PhotoImage only supports integer subsample/zoom, so we pick the
    integer factor closest to the requested width. Callers must keep a strong
    reference to the returned image (Tk garbage-collects unreferenced ones).
    """
    try:
        if not LOGO_FILE.is_file():
            return None
        logo = tk.PhotoImage(file=str(LOGO_FILE))
        factor = max(1, round(logo.width() / width_target))
        if factor > 1:
            logo = logo.subsample(factor, factor)
        return logo
    except Exception:  # noqa: BLE001 — a missing/corrupt logo must not break the GUI
        return None


def create_splash(root: tk.Tk) -> tk.Toplevel | None:
    """Welcome splash: ONLY the brand logo, centered (GUI only).

    Borderless, topmost, sized exactly to the logo on the theme's dark
    background. Returns None when branding is unavailable — the caller then
    reveals the main window immediately.
    """
    logo = load_logo_image(width_target=340)
    if logo is None:
        return None
    splash = tk.Toplevel(root, bg=THEME["bg"])
    splash.overrideredirect(True)  # borderless welcome card
    splash.attributes("-topmost", True)
    splash._images = [logo]  # noqa: SLF001 — keep references alive while shown

    tk.Label(splash, image=logo, bg=THEME["bg"]).pack(padx=10, pady=10)

    width, height = logo.width() + 20, logo.height() + 20
    splash.geometry(f"{width}x{height}")
    splash.update_idletasks()
    x = (splash.winfo_screenwidth() - width) // 2
    y = max(0, (splash.winfo_screenheight() - height) // 2 - 20)
    splash.geometry(f"+{x}+{y}")
    return splash


class SubtakeGUI:
    """Main application window (professional dark theme)."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.events: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self._output_customized = False  # user typed their own output folder?
        self._output_autowrite = False  # guard: we are writing output_var

        self.root.title("subtake — Subdomain Takeover & Asset Discovery")
        self.root.configure(bg=THEME["bg"])
        self.root.minsize(960, 640)
        self._center_window(1060, 760)

        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(family="Segoe UI", size=10)
        text_font = tkfont.nametofont("TkTextFont")
        text_font.configure(family="Segoe UI", size=10)

        self._apply_styles()
        self._build()
        # Keep the output folder in sync with the typed domain until the
        # user customizes it by hand (per-domain dedicated results folder).
        self.domain_var.trace_add("write", self._sync_output_with_domain)
        self.output_var.trace_add("write", self._on_output_written)
        # Pin the form column width so the results pane gets the wider share.
        self.root.update_idletasks()
        try:
            self.paned.sashpos(0, 330)
        except Exception:  # noqa: BLE001 — sashpos timing quirks on some WMs
            pass
        self.root.after(120, self._poll)

    # ------------------------------------------------------------- theming

    def _center_window(self, width: int, height: int) -> None:
        self.root.geometry(f"{width}x{height}")
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - width) // 2
        y = max(0, (self.root.winfo_screenheight() - height) // 2 - 20)
        self.root.geometry(f"+{x}+{y}")

    def _load_logo(self) -> tk.PhotoImage | None:
        """Header mark: the brand logo downscaled to ~72px (None when absent)."""
        return load_logo_image(width_target=72)

    def _apply_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(".", background=THEME["bg"], foreground=THEME["text"])
        style.configure("TFrame", background=THEME["bg"])
        style.configure("Card.TFrame", background=THEME["card"])
        style.configure("TLabel", background=THEME["bg"], foreground=THEME["text"])
        style.configure("Card.TLabel", background=THEME["card"], foreground=THEME["text"])
        style.configure(
            "Muted.TLabel", background=THEME["bg"], foreground=THEME["muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "CardMuted.TLabel", background=THEME["card"], foreground=THEME["muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "Header.TLabel", background=THEME["bg"], foreground=THEME["text"],
            font=("Segoe UI Semibold", 16),
        )
        style.configure(
            "Subheader.TLabel", background=THEME["bg"], foreground=THEME["muted"],
            font=("Segoe UI", 9),
        )

        # Cards (LabelFrames)
        style.configure(
            "Card.TLabelframe",
            background=THEME["card"],
            bordercolor=THEME["border"],
            relief="solid",
            borderwidth=1,
        )
        style.configure(
            "Card.TLabelframe.Label",
            background=THEME["card"],
            foreground=THEME["accent"],
            font=("Segoe UI Semibold", 10),
        )

        # Entries
        style.configure(
            "TEntry",
            fieldbackground=THEME["field"],
            background=THEME["card"],
            foreground=THEME["text"],
            bordercolor=THEME["border"],
            lightcolor=THEME["border"],
            darkcolor=THEME["border"],
            insertcolor=THEME["text"],
        )
        style.map("TEntry", bordercolor=[("focus", THEME["accent"])])

        # Checkbuttons
        style.configure(
            "TCheckbutton",
            background=THEME["card"],
            foreground=THEME["text"],
            focuscolor=THEME["accent"],
        )
        style.map("TCheckbutton", background=[("active", THEME["card"])])

        # Buttons
        style.configure(
            "TButton",
            background=THEME["card2"],
            foreground=THEME["text"],
            bordercolor=THEME["border"],
            lightcolor=THEME["card2"],
            darkcolor=THEME["card2"],
            padding=(10, 6),
        )
        style.map("TButton", background=[("active", "#1e2a48")])

        style.configure(
            "Start.TButton",
            background=THEME["accent_dark"],
            foreground="#06121f",
            font=("Segoe UI Semibold", 11),
            padding=(14, 8),
            bordercolor=THEME["accent_dark"],
            lightcolor=THEME["accent_dark"],
            darkcolor=THEME["accent_dark"],
        )
        style.map(
            "Start.TButton",
            background=[("active", THEME["accent"]), ("disabled", "#1e3a52")],
            foreground=[("disabled", "#5b7a92")],
        )
        style.configure(
            "Danger.TButton",
            background="#3b1420",
            foreground="#f87171",
            bordercolor="#7f1d1d",
            lightcolor="#3b1420",
            darkcolor="#3b1420",
            padding=(10, 6),
        )
        style.map("Danger.TButton", background=[("active", "#521a2c")])

        # Treeview
        style.configure(
            "Treeview",
            background=THEME["field"],
            fieldbackground=THEME["field"],
            foreground=THEME["text"],
            rowheight=26,
            bordercolor=THEME["border"],
        )
        style.configure(
            "Treeview.Heading",
            background=THEME["card2"],
            foreground=THEME["muted"],
            font=("Segoe UI Semibold", 9),
            bordercolor=THEME["border"],
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", "#173b5c")],
            foreground=[("selected", THEME["text"])],
        )

        # Paned window divider + scrollbars
        style.configure("TPanedwindow", background=THEME["bg"], bordercolor=THEME["bg"])
        style.configure(
            "Vertical.TScrollbar",
            background=THEME["card2"],
            troughcolor=THEME["bg"],
            bordercolor=THEME["bg"],
            arrowcolor=THEME["muted"],
        )
        style.configure(
            "Horizontal.TScrollbar",
            background=THEME["card2"],
            troughcolor=THEME["bg"],
            bordercolor=THEME["bg"],
            arrowcolor=THEME["muted"],
        )

    # ------------------------------------------------------------- building

    def _build(self) -> None:
        # ── Header banner: brand logo + title ────────────────────────────
        header = tk.Frame(self.root, bg=THEME["bg"])
        header.pack(fill="x", padx=14, pady=(12, 0))
        logo = self._load_logo()
        if logo is not None:
            self._logo_image = logo  # keep a reference — Tk GCs unreferenced images
            tk.Label(header, image=logo, bg=THEME["bg"]).pack(
                side="left", padx=(0, 12), pady=(0, 4)
            )
        try:
            if ICON_FILE.is_file():  # square render → crisp window/taskbar icon
                self._icon_image = tk.PhotoImage(file=str(ICON_FILE))
                self.root.iconphoto(True, self._icon_image)
        except Exception:  # noqa: BLE001 — cosmetic, never break the GUI
            pass
        title_box = tk.Frame(header, bg=THEME["bg"])
        title_box.pack(side="left")
        ttk.Label(title_box, text="subtake", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            title_box,
            text="Subdomain Takeover & Asset Discovery",
            style="Subheader.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            header,
            text=f"v{__version__}  ·  detect & report only  ·  never claims or exploits anything",
            style="Muted.TLabel",
        ).pack(side="right", pady=(8, 0))
        tk.Frame(self.root, bg=THEME["accent"], height=2).pack(fill="x")  # accent line

        # ── Authorization strip ──────────────────────────────────────────
        warning = tk.Label(
            self.root,
            text=(
                "⚠  AUTHORIZED USE ONLY — scan only domains you own or have written "
                "permission to test (bug-bounty scope / authorized pentest / lab targets)."
            ),
            bg=THEME["warn_bg"],
            fg=THEME["warn_fg"],
            font=("Segoe UI", 9),
            anchor="w",
            padx=12,
            pady=6,
        )
        warning.pack(fill="x", padx=14, pady=(8, 4))

        # ── Footer toolbar: reserved FIRST so it is always visible ───────
        self._build_footer()

        # ── Main split: scrollable form (left) / results (right) ─────────
        self.paned = ttk.PanedWindow(self.root, orient="horizontal")
        self.paned.pack(fill="both", expand=True, padx=14, pady=(6, 4))

        form_wrap = ttk.Frame(self.paned)
        self.paned.add(form_wrap, weight=0)

        results = ttk.Frame(self.paned)
        self.paned.add(results, weight=1)

        # Scrollable left column — no action button is ever cut off again.
        self._form_canvas = tk.Canvas(form_wrap, bg=THEME["bg"], highlightthickness=0)
        form_scroll = ttk.Scrollbar(form_wrap, orient="vertical", command=self._form_canvas.yview)
        self._form_canvas.configure(yscrollcommand=form_scroll.set)
        form_scroll.pack(side="right", fill="y")
        self._form_canvas.pack(side="left", fill="both", expand=True)
        form = ttk.Frame(self._form_canvas, style="TFrame")
        self._form_window = self._form_canvas.create_window((0, 0), window=form, anchor="nw")
        form.bind(
            "<Configure>",
            lambda _e: self._form_canvas.configure(scrollregion=self._form_canvas.bbox("all")),
        )
        self._form_canvas.bind(
            "<Configure>",
            lambda e: self._form_canvas.itemconfigure(self._form_window, width=e.width),
        )
        if IS_WINDOWS:
            self.root.bind_all("<MouseWheel>", self._on_form_mousewheel, add="+")
        else:
            self._form_canvas.bind(
                "<Button-4>", lambda _e: self._form_canvas.yview_scroll(-1, "units"), add="+"
            )
            self._form_canvas.bind(
                "<Button-5>", lambda _e: self._form_canvas.yview_scroll(1, "units"), add="+"
            )

        # ---- left column: target + options + formats ---------------------
        target_card = ttk.LabelFrame(form, text=" 🎯 Target domain ", style="Card.TLabelframe")
        target_card.pack(fill="x")
        inner = ttk.Frame(target_card, style="Card.TFrame")
        inner.pack(fill="x", padx=10, pady=8)
        self.domain_var = tk.StringVar()
        domain_entry = ttk.Entry(inner, textvariable=self.domain_var, font=("Segoe UI", 12))
        domain_entry.pack(fill="x", ipady=3)
        domain_entry.bind("<Return>", lambda _e: self._start_scan())
        self.domain_entry = domain_entry  # referenced by the selftest
        attach_clipboard_menu(domain_entry)
        ttk.Label(
            inner, text="e.g. example.com  —  press Enter to start", style="CardMuted.TLabel"
        ).pack(anchor="w", pady=(4, 0))

        options = ttk.LabelFrame(form, text=" ⚙ Scan options ", style="Card.TLabelframe")
        options.pack(fill="x", pady=(10, 0))
        opt = ttk.Frame(options, style="Card.TFrame")
        opt.pack(fill="x", padx=10, pady=8)
        opt.columnconfigure(1, weight=1)

        ttk.Label(opt, text="Threads:", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        self.threads_var = tk.StringVar(value="100")
        threads_entry = ttk.Entry(opt, textvariable=self.threads_var, width=8)
        threads_entry.grid(row=0, column=1, sticky="we")
        attach_clipboard_menu(threads_entry)

        ttk.Label(opt, text="Timeout (s):", style="Card.TLabel").grid(
            row=1, column=0, sticky="w", pady=(6, 0)
        )
        self.timeout_var = tk.StringVar(value="10")
        timeout_entry = ttk.Entry(opt, textvariable=self.timeout_var, width=8)
        timeout_entry.grid(row=1, column=1, sticky="we", pady=(6, 0))
        attach_clipboard_menu(timeout_entry)

        ttk.Label(opt, text="Resolvers:", style="Card.TLabel").grid(
            row=2, column=0, sticky="w", pady=(6, 0)
        )
        self.resolvers_var = tk.StringVar(value="1.1.1.1 8.8.8.8 9.9.9.9")
        resolvers_entry = ttk.Entry(opt, textvariable=self.resolvers_var)
        resolvers_entry.grid(row=2, column=1, sticky="we", pady=(6, 0))
        attach_clipboard_menu(resolvers_entry)

        self.skip_brute_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            opt, text="Skip brute-force (passive only)", variable=self.skip_brute_var
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))

        ttk.Label(opt, text="Wordlist:", style="Card.TLabel").grid(
            row=4, column=0, sticky="w", pady=(6, 0)
        )
        self.wordlist_var = tk.StringVar()
        wl_row = ttk.Frame(opt, style="Card.TFrame")
        wl_row.grid(row=4, column=1, sticky="we", pady=(6, 0))
        wl_row.columnconfigure(0, weight=1)
        wordlist_entry = ttk.Entry(wl_row, textvariable=self.wordlist_var)
        wordlist_entry.grid(row=0, column=0, sticky="we")
        attach_clipboard_menu(wordlist_entry)
        ttk.Button(wl_row, text="…", width=3, command=self._browse_wordlist).grid(
            row=0, column=1, padx=(4, 0)
        )
        ttk.Label(opt, text="(empty = built-in 200+ word list)", style="CardMuted.TLabel").grid(
            row=5, column=0, columnspan=2, sticky="w"
        )

        ttk.Label(opt, text="Output folder:", style="Card.TLabel").grid(
            row=6, column=0, sticky="w", pady=(6, 0)
        )
        self.output_var = tk.StringVar(value=str(RESULTS_DIR / "gui"))
        out_row = ttk.Frame(opt, style="Card.TFrame")
        out_row.grid(row=6, column=1, sticky="we", pady=(6, 0))
        out_row.columnconfigure(0, weight=1)
        output_entry = ttk.Entry(out_row, textvariable=self.output_var)
        output_entry.grid(row=0, column=0, sticky="we")
        attach_clipboard_menu(output_entry)
        ttk.Button(out_row, text="…", width=3, command=self._browse_output).grid(
            row=0, column=1, padx=(4, 0)
        )

        formats_card = ttk.LabelFrame(form, text=" 🧾 Report formats ", style="Card.TLabelframe")
        formats_card.pack(fill="x", pady=(10, 0))
        formats = ttk.Frame(formats_card, style="Card.TFrame")
        formats.pack(fill="x", padx=10, pady=6)
        self.format_vars: dict[str, tk.BooleanVar] = {}
        for fmt in ("html", "csv", "markdown", "json", "excel"):
            var = tk.BooleanVar(value=True)
            self.format_vars[fmt] = var
            ttk.Checkbutton(formats, text=fmt, variable=var).pack(side="left", padx=(0, 10))

        ttk.Label(
            form,
            text="Results land in data/output/<domain>/ — one dedicated folder per target.",
            style="Muted.TLabel",
            wraplength=300,
            justify="left",
        ).pack(anchor="w", pady=(10, 4))

        # ---- right column: log + findings --------------------------------
        log_card = ttk.LabelFrame(results, text=" 📜 Live log ", style="Card.TLabelframe")
        log_card.pack(fill="both", expand=True)
        self.log_text = tk.Text(
            log_card,
            height=10,
            state="disabled",
            font=("Consolas", 9),
            bg=THEME["field"],
            fg=THEME["text"],
            insertbackground=THEME["text"],
            relief="flat",
            padx=8,
            pady=6,
            wrap="none",
        )
        for tag, color in (
            ("warn", THEME["warn_fg"]),
            ("error", "#f87171"),
            ("ok", THEME["ok"]),
            ("phase", THEME["accent"]),
        ):
            self.log_text.tag_configure(tag, foreground=color)
        log_scroll = ttk.Scrollbar(log_card, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True, side="left")

        find_card = ttk.LabelFrame(
            results,
            text=" 🎯 Findings — advisory, verify manually before acting ",
            style="Card.TLabelframe",
        )
        find_card.pack(fill="both", expand=True, pady=(10, 0))
        columns = ("severity", "confidence", "type", "subdomain", "service")
        self.tree = ttk.Treeview(find_card, columns=columns, show="headings", height=7)
        headings = {"severity": "SEV", "confidence": "CONF.", "type": "TYPE",
                    "subdomain": "SUBDOMAIN", "service": "SERVICE"}
        widths = {"severity": 75, "confidence": 80, "type": 190, "subdomain": 225, "service": 125}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w", stretch=True)
        for severity, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(severity, foreground=color)
        self.tree.tag_configure("stripe", background="#0c1526")
        find_scroll = ttk.Scrollbar(find_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=find_scroll.set)
        find_scroll.pack(side="right", fill="y")
        h_scroll = ttk.Scrollbar(find_card, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscrollcommand=h_scroll.set)
        h_scroll.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True, side="left")

        legend = tk.Frame(results, bg=THEME["bg"])
        legend.pack(anchor="w", pady=(6, 0))
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            tk.Label(
                legend, text="●", fg=SEVERITY_COLORS[severity], bg=THEME["bg"],
                font=("Segoe UI", 9),
            ).pack(side="left")
            ttk.Label(legend, text=severity, style="Muted.TLabel").pack(side="left", padx=(2, 10))

        self.summary_var = tk.StringVar(value="")
        ttk.Label(results, textvariable=self.summary_var, style="Muted.TLabel").pack(
            anchor="w", pady=(2, 0)
        )

    def _build_footer(self) -> None:
        """Always-visible action toolbar: start / open / clear + live state."""
        footer = tk.Frame(
            self.root,
            bg=THEME["card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
        )
        footer.pack(fill="x", side="bottom", padx=14, pady=(4, 10))

        self.start_button = ttk.Button(
            footer, text="▶    START SCAN", style="Start.TButton", command=self._start_scan
        )
        self.start_button.pack(side="left", padx=(4, 10), pady=8, ipadx=8)

        self.open_button = ttk.Button(
            footer, text="📂  Open output folder", command=self._open_output, state="disabled"
        )
        self.open_button.pack(side="left", padx=4, pady=8)

        self.clean_button = ttk.Button(
            footer, text="🗑  Clear saved results", style="Danger.TButton",
            command=self._clear_results,
        )
        self.clean_button.pack(side="left", padx=4, pady=8)

        self.progress = ttk.Progressbar(footer, mode="indeterminate", length=130)
        self.progress.pack(side="right", padx=(8, 12), pady=8)

        self.state_dot = tk.Label(
            footer, text="●", fg=THEME["ok"], bg=THEME["card"], font=("Segoe UI", 13)
        )
        self.state_dot.pack(side="right")
        self.status_var = tk.StringVar(
            value="Ready — enter a target domain and press Start scan."
        )
        ttk.Label(footer, textvariable=self.status_var, style="Card.TLabel").pack(
            side="right", padx=(0, 6), pady=8
        )

    def _on_form_mousewheel(self, event) -> None:
        """Scroll the left form when the pointer hovers over it (Windows)."""
        widget = self.root.winfo_containing(event.x_root, event.y_root)
        if widget is None:
            return
        path = str(widget)
        if path.startswith(str(self._form_canvas)):
            self._form_canvas.yview_scroll(-1 * (event.delta // 120), "units")

    def _set_state(self, state: str) -> None:
        """Drive the footer state dot (running=amber, ok=green, error=red)."""
        colors = {"running": THEME["warn_fg"], "ok": THEME["ok"], "error": "#f87171"}
        self.state_dot.configure(fg=colors.get(state, THEME["muted"]))

    # ------------------------------------------------------------ actions

    def _browse_wordlist(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose a wordlist", filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.wordlist_var.set(path)

    def _browse_output(self) -> None:
        path = filedialog.askdirectory(title="Choose the output folder")
        if path:
            self.output_var.set(path)

    def _open_output(self) -> None:
        _open_folder(Path(self.output_var.get() or RESULTS_DIR / "gui"))

    def _on_output_written(self, *_args) -> None:
        """Mark the output folder as user-customized (unless we wrote it)."""
        if not self._output_autowrite:
            self._output_customized = True

    def _sync_output_with_domain(self, *_args) -> None:
        """Point the output folder at data/output/<domain>/ as the user types.

        Stops as soon as the user types a folder of their own — their choice
        wins and we never overwrite it again.
        """
        if self._output_customized:
            return
        raw = self.domain_var.get().strip()
        if not raw:
            return
        try:
            domain = normalize_domain(raw)
        except InvalidDomainError:
            return  # mid-typing garbage — wait for a valid domain
        self._output_autowrite = True
        try:
            self.output_var.set(str(domain_output_dir(domain, "gui")))
        finally:
            self._output_autowrite = False

    def _start_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Busy", "A scan is already running.")
            return
        formats = [fmt for fmt, var in self.format_vars.items() if var.get()]
        try:
            job = build_job(
                domain_raw=self.domain_var.get(),
                threads_raw=self.threads_var.get(),
                timeout_raw=self.timeout_var.get(),
                resolvers_raw=self.resolvers_var.get(),
                wordlist_raw=self.wordlist_var.get(),
                output_dir_raw=self.output_var.get(),
                skip_brute=self.skip_brute_var.get(),
                formats_checked=formats,
            )
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return

        self._append_log(f"=== Scan started for {job['domain']} ===", "phase")
        self.tree.delete(*self.tree.get_children())
        self.summary_var.set("")
        self.open_button.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.clean_button.configure(state="disabled")
        self._set_state("running")
        self.progress.start(12)
        self.worker = threading.Thread(target=run_scan_job, args=(job, self.events), daemon=True)
        self.worker.start()

    def _clear_results(self) -> None:
        """Delete the stored scan records for the current domain (confirmed).

        Destructive by design — every step asks the user first: the SQLite
        rows go after one confirmation, and the whole results folder only
        after a second one (and only for the default per-domain folder).
        """
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Busy", "Wait for the running scan to finish first.")
            return
        try:
            domain = normalize_domain(self.domain_var.get())
        except InvalidDomainError as exc:
            messagebox.showerror("Invalid domain", str(exc))
            return
        out_dir = Path(self.output_var.get() or domain_output_dir(domain, "gui"))
        db_path = out_dir / "subtake.db"
        if not db_path.is_file():
            messagebox.showinfo("Nothing to clear", f"No stored records found:\n{db_path}")
            return
        if not messagebox.askyesno(
            "Confirm deletion",
            f"Delete ALL saved scan records for\n\n{domain}\n\nfrom:\n{db_path}?",
        ):
            return
        try:
            db = ScanDatabase(db_path)
            counts = db.delete_domain_records(domain)
            db.close()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Delete failed", str(exc))
            return
        if counts["scans"] == 0:
            messagebox.showinfo(
                "Nothing to clear", f"No records for {domain} in:\n{db_path}"
            )
            return
        self._append_log(
            f"=== Cleared records for {domain}: {counts['scans']} scan(s), "
            f"{counts['subdomains']} subdomain row(s), {counts['dns_records']} DNS "
            f"record(s), {counts['findings']} finding(s) ===",
            "ok",
        )
        self.status_var.set("Saved records cleared.")
        if not messagebox.askyesno(
            "Also delete files?",
            f"Also delete the whole results folder?\n{out_dir}",
        ):
            return
        if out_dir != domain_output_dir(domain, "gui"):
            messagebox.showwarning(
                "Not allowed",
                "Folder deletion is only allowed for the default per-domain folder.",
            )
            return
        if out_dir.is_dir():
            shutil.rmtree(out_dir)
            self._append_log(f"=== Results folder deleted: {out_dir} ===", "ok")
            self.open_button.configure(state="disabled")
            self.status_var.set("Results folder deleted.")

    # ------------------------------------------------------------- polling

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._append_log(payload + "\n")
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "findings":
                    self._show_findings(payload)
                elif kind == "reports":
                    self.open_button.configure(state="normal")
                elif kind == "done":
                    self.status_var.set(payload)
                    self._append_log(f"=== {payload} ===", "ok")
                    self.progress.stop()
                    self._set_state("ok")
                    self.start_button.configure(state="normal")
                    self.clean_button.configure(state="normal")
                elif kind == "error":
                    self.status_var.set("Scan failed — see the log for details.")
                    self._append_log(f"[ERROR] {payload}", "error")
                    self.progress.stop()
                    self._set_state("error")
                    self.start_button.configure(state="normal")
                    self.clean_button.configure(state="normal")
                    messagebox.showerror("Scan failed", payload)
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _append_log(self, line: str, tag: str | None = None) -> None:
        if tag is None:
            lowered = line.lower()
            if "[error]" in lowered or "error" in lowered:
                tag = "error"
            elif "warning" in lowered:
                tag = "warn"
            elif lowered.startswith("──") or lowered.startswith("==="):
                tag = "phase"
            elif "✔" in line:
                tag = "ok"
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n", (tag,) if tag else ())
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _show_findings(self, result: Phase3Result) -> None:
        self.tree.delete(*self.tree.get_children())
        findings = sort_findings_for_display(result.findings)
        for index, finding in enumerate(findings):
            tags = [finding.severity] + (["stripe"] if index % 2 else [])
            self.tree.insert(
                "",
                "end",
                values=(
                    finding.severity,
                    finding.confidence,
                    finding.type,
                    finding.subdomain,
                    finding.service,
                ),
                tags=tags,
            )
        summary = result.summary
        self.summary_var.set(
            f"Scanned: {summary.get('total_scanned', 0)}    "
            f"Vulnerable (HIGH): {summary.get('vulnerable', 0)}    "
            f"MEDIUM: {summary.get('by_confidence', {}).get('MEDIUM', 0)}    "
            f"LOW: {summary.get('by_confidence', {}).get('LOW', 0)}"
        )


def main() -> int:
    """Entry point for the GUI (``subtake-gui`` / ``python -m src.gui``)."""
    if not TK_AVAILABLE:
        print(
            "GUI is unavailable in this environment (tkinter not installed).\n"
            "Use the CLI instead: python -m src.cli --help"
        )
        return 3
    _enable_windows_dpi_awareness()
    root = tk.Tk()
    root.withdraw()  # hidden while the welcome splash shows
    SubtakeGUI(root)  # builds (hidden) + applies the dark ttk styles first
    splash = create_splash(root)  # styled labels now inherit the dark theme

    def _reveal() -> None:
        """Close the welcome splash and show the main window."""
        if splash is not None:
            try:
                splash.destroy()
            except Exception:  # noqa: BLE001 — already gone
                pass
        root.deiconify()

    if splash is not None:
        root.after(2000, _reveal)  # welcome splash shows for ~2s
    else:
        _reveal()
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
