"""
IBM Bob Hackathon — Security Code Review Agent
GUI front-end (app.py)
======================
Modern dark-themed desktop application built with tkinter + ttk.
Wraps security_agent.py — no extra dependencies beyond stdlib + Pillow.

Run:   python app.py
Build: pyinstaller security_agent.spec
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import queue

# ── Make sure the core engine is importable whether running as script or .exe ──
if getattr(sys, "frozen", False):
    _BASE = sys._MEIPASS
else:
    _BASE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, _BASE)
import security_agent as engine  # the script we already wrote

# ── Palette ────────────────────────────────────────────────────────────────────
BG          = "#0d1117"   # GitHub-dark background
SURFACE     = "#161b22"   # card / panel surface
SURFACE2    = "#1c2128"   # slightly lighter surface
BORDER      = "#30363d"   # subtle border
TEXT        = "#e6edf3"   # primary text
MUTED       = "#7d8590"   # secondary / muted text
ACCENT      = "#238636"   # IBM green / success
ACCENT_HOV  = "#2ea043"
DANGER      = "#da3633"   # Critical red
WARN        = "#d29922"   # High orange  / warning
INFO        = "#1f6feb"   # Medium blue
SUCCESS     = "#238636"   # Low green

RISK_COLORS = {
    "Critical": DANGER,
    "High":     "#e05c2e",
    "Medium":   WARN,
    "Low":      SUCCESS,
}
RISK_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}

FONT_FAMILY = "Segoe UI"
FONT_MONO   = "Consolas"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _font(size=11, weight="normal"):
    return (FONT_FAMILY, size, weight)


def _mono(size=10):
    return (FONT_MONO, size, "normal")


# ── Main application window ────────────────────────────────────────────────────

class SecurityAgentApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Security Code Review Agent  ·  IBM Bob Hackathon")
        self.geometry("1100x760")
        self.minsize(900, 600)
        self.configure(bg=BG)

        # Queue for thread → UI communication
        self._queue: queue.Queue = queue.Queue()

        # State
        self._scan_thread: threading.Thread | None = None
        self._report_text: str = ""
        self._issues: list[engine.SecurityIssue] = []

        self._build_styles()
        self._build_ui()
        self._poll_queue()

    # ── ttk styles ─────────────────────────────────────────────────────────────

    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".",
            background=BG, foreground=TEXT,
            font=_font(11), borderwidth=0, relief="flat")

        style.configure("TFrame", background=BG)
        style.configure("Surface.TFrame", background=SURFACE)
        style.configure("Surface2.TFrame", background=SURFACE2)

        style.configure("TLabel",
            background=BG, foreground=TEXT, font=_font(11))
        style.configure("Muted.TLabel",
            background=BG, foreground=MUTED, font=_font(10))
        style.configure("Surface.TLabel",
            background=SURFACE, foreground=TEXT, font=_font(11))
        style.configure("Heading.TLabel",
            background=BG, foreground=TEXT, font=_font(14, "bold"))
        style.configure("Hero.TLabel",
            background=BG, foreground=TEXT, font=_font(22, "bold"))
        style.configure("Sub.TLabel",
            background=BG, foreground=MUTED, font=_font(11))

        # Primary action button (green)
        style.configure("Primary.TButton",
            background=ACCENT, foreground="#ffffff",
            font=_font(11, "bold"), padding=(16, 8),
            borderwidth=0, relief="flat", cursor="hand2")
        style.map("Primary.TButton",
            background=[("active", ACCENT_HOV), ("disabled", BORDER)],
            foreground=[("disabled", MUTED)])

        # Secondary / ghost button
        style.configure("Secondary.TButton",
            background=SURFACE2, foreground=TEXT,
            font=_font(10), padding=(12, 6),
            borderwidth=1, relief="flat", cursor="hand2")
        style.map("Secondary.TButton",
            background=[("active", BORDER)])

        # Entry
        style.configure("TEntry",
            fieldbackground=SURFACE2, foreground=TEXT,
            insertcolor=TEXT, borderwidth=1,
            relief="flat", padding=(10, 8),
            font=_font(11))
        style.map("TEntry",
            fieldbackground=[("focus", SURFACE2)],
            bordercolor=[("focus", INFO), ("!focus", BORDER)])

        # Notebook tabs
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab",
            background=SURFACE, foreground=MUTED,
            font=_font(10, "bold"), padding=(16, 8))
        style.map("TNotebook.Tab",
            background=[("selected", SURFACE2)],
            foreground=[("selected", TEXT)])

        # Treeview (findings table)
        style.configure("Treeview",
            background=SURFACE, foreground=TEXT,
            fieldbackground=SURFACE, rowheight=28,
            font=_font(10), borderwidth=0)
        style.configure("Treeview.Heading",
            background=SURFACE2, foreground=TEXT,
            font=_font(10, "bold"), relief="flat")
        style.map("Treeview",
            background=[("selected", INFO)],
            foreground=[("selected", "#ffffff")])

        # Progressbar
        style.configure("Accent.Horizontal.TProgressbar",
            troughcolor=SURFACE, background=ACCENT,
            borderwidth=0, thickness=4)

        # Scrollbar
        style.configure("TScrollbar",
            background=SURFACE, troughcolor=BG,
            arrowcolor=MUTED, borderwidth=0)

    # ── UI layout ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Top header bar ────────────────────────────────────────────────────
        header = tk.Frame(self, bg=SURFACE, height=56)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        # Shield icon (drawn with canvas — no external image needed for header)
        shield = tk.Canvas(header, width=36, height=36,
                           bg=SURFACE, highlightthickness=0)
        shield.pack(side="left", padx=(16, 8), pady=10)
        self._draw_shield(shield, 18, 18, 16, ACCENT)

        tk.Label(header, text="Security Code Review Agent",
                 bg=SURFACE, fg=TEXT,
                 font=_font(14, "bold")).pack(side="left", pady=10)

        tk.Label(header, text="IBM Bob Hackathon",
                 bg=SURFACE, fg=MUTED,
                 font=_font(10)).pack(side="left", padx=12, pady=10)

        # IBM logo text on the right
        tk.Label(header, text="IBM  ",
                 bg=SURFACE, fg="#4589ff",
                 font=_font(13, "bold")).pack(side="right", padx=16, pady=10)

        # Thin accent line under header
        tk.Frame(self, bg=ACCENT, height=2).pack(fill="x")

        # ── Main body (two columns) ───────────────────────────────────────────
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=0, pady=0)

        # Left panel — input + summary cards
        left = tk.Frame(body, bg=BG, width=320)
        left.pack(side="left", fill="y", padx=0, pady=0)
        left.pack_propagate(False)

        self._build_left_panel(left)

        # Divider
        tk.Frame(body, bg=BORDER, width=1).pack(side="left", fill="y")

        # Right panel — notebook with findings / raw report
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        self._build_right_panel(right)

        # ── Status bar ────────────────────────────────────────────────────────
        self._build_status_bar()

    # ── Left panel ─────────────────────────────────────────────────────────────

    def _build_left_panel(self, parent):
        pad = dict(padx=20, pady=0)

        # Section label
        tk.Label(parent, text="Repository", bg=BG, fg=MUTED,
                 font=_font(9, "bold")).pack(anchor="w", padx=20, pady=(20, 4))

        # URL entry
        entry_frame = tk.Frame(parent, bg=BORDER, bd=0)
        entry_frame.pack(fill="x", padx=20, pady=(0, 4))
        inner = tk.Frame(entry_frame, bg=SURFACE2, bd=0)
        inner.pack(fill="x", padx=1, pady=1)

        self._url_var = tk.StringVar(value="https://github.com/owner/repo")
        self._url_entry = tk.Entry(
            inner, textvariable=self._url_var,
            bg=SURFACE2, fg=TEXT, insertbackground=TEXT,
            relief="flat", font=_font(11),
            bd=0
        )
        self._url_entry.pack(fill="x", padx=10, pady=8)
        self._url_entry.bind("<FocusIn>",  self._on_entry_focus)
        self._url_entry.bind("<FocusOut>", self._on_entry_blur)

        # GitHub token
        tk.Label(parent, text="GitHub Token  (optional)",
                 bg=BG, fg=MUTED, font=_font(9, "bold")).pack(
                     anchor="w", padx=20, pady=(12, 4))

        tok_frame = tk.Frame(parent, bg=BORDER)
        tok_frame.pack(fill="x", padx=20, pady=(0, 4))
        tok_inner = tk.Frame(tok_frame, bg=SURFACE2)
        tok_inner.pack(fill="x", padx=1, pady=1)

        self._token_var = tk.StringVar(
            value=os.environ.get("GITHUB_TOKEN", ""))
        self._token_entry = tk.Entry(
            tok_inner, textvariable=self._token_var,
            show="•", bg=SURFACE2, fg=TEXT, insertbackground=TEXT,
            relief="flat", font=_font(11), bd=0
        )
        self._token_entry.pack(fill="x", padx=10, pady=8)

        # Output file
        tk.Label(parent, text="Save Report To  (optional)",
                 bg=BG, fg=MUTED, font=_font(9, "bold")).pack(
                     anchor="w", padx=20, pady=(12, 4))

        out_row = tk.Frame(parent, bg=BG)
        out_row.pack(fill="x", padx=20, pady=(0, 4))

        out_frame = tk.Frame(out_row, bg=BORDER)
        out_frame.pack(side="left", fill="x", expand=True)
        out_inner = tk.Frame(out_frame, bg=SURFACE2)
        out_inner.pack(fill="x", padx=1, pady=1)

        self._output_var = tk.StringVar()
        tk.Entry(out_inner, textvariable=self._output_var,
                 bg=SURFACE2, fg=TEXT, insertbackground=TEXT,
                 relief="flat", font=_font(11), bd=0).pack(
                     fill="x", padx=10, pady=8)

        tk.Button(out_row, text="…", bg=SURFACE2, fg=TEXT,
                  relief="flat", font=_font(11), cursor="hand2", bd=0,
                  command=self._browse_output,
                  padx=8).pack(side="left", padx=(4, 0))

        # ── Scan button ───────────────────────────────────────────────────────
        self._scan_btn = tk.Button(
            parent, text="▶  Start Scan",
            bg=ACCENT, fg="#ffffff", relief="flat",
            font=_font(12, "bold"), cursor="hand2",
            activebackground=ACCENT_HOV, activeforeground="#ffffff",
            padx=0, pady=10, bd=0,
            command=self._start_scan,
        )
        self._scan_btn.pack(fill="x", padx=20, pady=(20, 4))

        self._stop_btn = tk.Button(
            parent, text="⏹  Stop",
            bg=SURFACE2, fg=MUTED, relief="flat",
            font=_font(10), cursor="hand2",
            activebackground=BORDER, activeforeground=TEXT,
            padx=0, pady=8, bd=0, state="disabled",
            command=self._stop_scan,
        )
        self._stop_btn.pack(fill="x", padx=20, pady=(0, 16))

        # ── Divider ───────────────────────────────────────────────────────────
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=20, pady=8)

        # ── Summary cards ─────────────────────────────────────────────────────
        tk.Label(parent, text="Scan Results", bg=BG, fg=MUTED,
                 font=_font(9, "bold")).pack(anchor="w", padx=20, pady=(8, 8))

        cards = tk.Frame(parent, bg=BG)
        cards.pack(fill="x", padx=20)

        self._count_vars = {}
        for level, color in [
            ("Critical", DANGER), ("High", "#e05c2e"),
            ("Medium", WARN),     ("Low", SUCCESS)
        ]:
            card = tk.Frame(cards, bg=SURFACE2, bd=0)
            card.pack(fill="x", pady=3)
            left_stripe = tk.Frame(card, bg=color, width=4)
            left_stripe.pack(side="left", fill="y")
            emoji = RISK_EMOJI[level]
            tk.Label(card, text=f"{emoji} {level}",
                     bg=SURFACE2, fg=TEXT, font=_font(10),
                     padx=10, pady=6).pack(side="left")
            var = tk.StringVar(value="—")
            self._count_vars[level] = var
            tk.Label(card, textvariable=var,
                     bg=SURFACE2, fg=color,
                     font=_font(14, "bold"),
                     padx=10).pack(side="right")

        # Files scanned
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=20, pady=(16, 8))
        files_row = tk.Frame(parent, bg=BG)
        files_row.pack(fill="x", padx=20)
        tk.Label(files_row, text="Files analysed",
                 bg=BG, fg=MUTED, font=_font(9)).pack(side="left")
        self._files_var = tk.StringVar(value="—")
        tk.Label(files_row, textvariable=self._files_var,
                 bg=BG, fg=TEXT, font=_font(11, "bold")).pack(side="right")

        # Export button
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=20, pady=(16, 8))
        self._export_btn = tk.Button(
            parent, text="💾  Export Report",
            bg=SURFACE2, fg=TEXT, relief="flat",
            font=_font(10), cursor="hand2",
            activebackground=BORDER, activeforeground=TEXT,
            padx=0, pady=8, bd=0,
            command=self._export_report, state="disabled",
        )
        self._export_btn.pack(fill="x", padx=20)

    # ── Right panel ────────────────────────────────────────────────────────────

    def _build_right_panel(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.pack(fill="both", expand=True)

        # Tab 1 — Findings table
        tab_findings = tk.Frame(notebook, bg=BG)
        notebook.add(tab_findings, text="  🔍  Findings  ")
        self._build_findings_tab(tab_findings)

        # Tab 2 — Log / console
        tab_log = tk.Frame(notebook, bg=BG)
        notebook.add(tab_log, text="  📋  Scan Log  ")
        self._build_log_tab(tab_log)

        # Tab 3 — Raw Markdown report
        tab_report = tk.Frame(notebook, bg=BG)
        notebook.add(tab_report, text="  📄  Report  ")
        self._build_report_tab(tab_report)

    def _build_findings_tab(self, parent):
        # Toolbar
        toolbar = tk.Frame(parent, bg=SURFACE2, height=38)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        tk.Label(toolbar, text="Filter:",
                 bg=SURFACE2, fg=MUTED, font=_font(9)).pack(side="left", padx=(12, 4), pady=8)

        self._filter_var = tk.StringVar(value="All")
        for level in ("All", "Critical", "High", "Medium", "Low"):
            color = RISK_COLORS.get(level, TEXT)
            btn = tk.Button(
                toolbar, text=level,
                bg=SURFACE2, fg=color, relief="flat",
                font=_font(9, "bold"), cursor="hand2",
                activebackground=BORDER, activeforeground=color,
                bd=0, padx=10, pady=0,
                command=lambda l=level: self._apply_filter(l),
            )
            btn.pack(side="left", pady=4, padx=2)

        # Treeview
        cols = ("risk", "title", "file", "line")
        self._tree = ttk.Treeview(parent, columns=cols, show="headings",
                                   selectmode="browse")
        self._tree.heading("risk",  text="Risk",  anchor="w")
        self._tree.heading("title", text="Finding", anchor="w")
        self._tree.heading("file",  text="File",   anchor="w")
        self._tree.heading("line",  text="Line",   anchor="center")

        self._tree.column("risk",  width=100, minwidth=80,  anchor="w")
        self._tree.column("title", width=260, minwidth=160, anchor="w")
        self._tree.column("file",  width=260, minwidth=160, anchor="w")
        self._tree.column("line",  width=60,  minwidth=50,  anchor="center")

        vsb = ttk.Scrollbar(parent, orient="vertical",
                            command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

        # Tag colours per risk level
        for level, color in RISK_COLORS.items():
            self._tree.tag_configure(level, foreground=color)

        self._tree.bind("<<TreeviewSelect>>", self._on_finding_select)

        # Detail pane
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")
        detail = tk.Frame(parent, bg=SURFACE, height=180)
        detail.pack(fill="x")
        detail.pack_propagate(False)

        self._detail_text = tk.Text(
            detail, bg=SURFACE, fg=TEXT,
            relief="flat", bd=0, font=_mono(10),
            wrap="word", state="disabled",
            padx=14, pady=10,
        )
        dsb = ttk.Scrollbar(detail, orient="vertical",
                            command=self._detail_text.yview)
        self._detail_text.configure(yscrollcommand=dsb.set)
        dsb.pack(side="right", fill="y")
        self._detail_text.pack(fill="both", expand=True)

        # Configure text tags
        self._detail_text.tag_configure("heading",
            font=_font(11, "bold"), foreground=TEXT)
        self._detail_text.tag_configure("danger",
            font=_font(10), foreground=DANGER)
        self._detail_text.tag_configure("code",
            font=_mono(10), foreground="#79c0ff",
            background=SURFACE2)
        self._detail_text.tag_configure("fix",
            font=_mono(10), foreground="#56d364",
            background=SURFACE2)
        self._detail_text.tag_configure("muted",
            font=_font(10), foreground=MUTED)

    def _build_log_tab(self, parent):
        self._log_text = tk.Text(
            parent, bg=BG, fg=MUTED,
            relief="flat", bd=0, font=_mono(10),
            wrap="none", state="disabled",
            padx=14, pady=10,
        )
        sb_v = ttk.Scrollbar(parent, orient="vertical",
                             command=self._log_text.yview)
        sb_h = ttk.Scrollbar(parent, orient="horizontal",
                             command=self._log_text.xview)
        self._log_text.configure(yscrollcommand=sb_v.set,
                                  xscrollcommand=sb_h.set)
        sb_v.pack(side="right", fill="y")
        sb_h.pack(side="bottom", fill="x")
        self._log_text.pack(fill="both", expand=True)

        self._log_text.tag_configure("ok",     foreground=SUCCESS)
        self._log_text.tag_configure("warn",   foreground=WARN)
        self._log_text.tag_configure("error",  foreground=DANGER)
        self._log_text.tag_configure("header", foreground=ACCENT,
                                     font=_font(10, "bold"))
        self._log_text.tag_configure("muted",  foreground=MUTED)

    def _build_report_tab(self, parent):
        self._report_text_widget = tk.Text(
            parent, bg=BG, fg=TEXT,
            relief="flat", bd=0, font=_mono(10),
            wrap="none", state="disabled",
            padx=14, pady=10,
        )
        sb_v = ttk.Scrollbar(parent, orient="vertical",
                             command=self._report_text_widget.yview)
        sb_h = ttk.Scrollbar(parent, orient="horizontal",
                             command=self._report_text_widget.xview)
        self._report_text_widget.configure(yscrollcommand=sb_v.set,
                                            xscrollcommand=sb_h.set)
        sb_v.pack(side="right", fill="y")
        sb_h.pack(side="bottom", fill="x")
        self._report_text_widget.pack(fill="both", expand=True)

    # ── Status bar ─────────────────────────────────────────────────────────────

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=SURFACE2, height=30)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._progress = ttk.Progressbar(
            bar, mode="indeterminate", length=120,
            style="Accent.Horizontal.TProgressbar")
        self._progress.pack(side="right", padx=12, pady=7)

        self._status_var = tk.StringVar(value="Ready  ·  Provide a GitHub URL and press Start Scan")
        tk.Label(bar, textvariable=self._status_var,
                 bg=SURFACE2, fg=MUTED,
                 font=_font(9)).pack(side="left", padx=12)

    # ── Shield canvas drawing ──────────────────────────────────────────────────

    def _draw_shield(self, canvas, cx, cy, r, color):
        """Draw a simple shield polygon on a canvas."""
        pts = [
            cx,       cy - r,
            cx + r,   cy - r * 0.4,
            cx + r,   cy + r * 0.2,
            cx,       cy + r,
            cx - r,   cy + r * 0.2,
            cx - r,   cy - r * 0.4,
        ]
        canvas.create_polygon(pts, fill=color, outline="", smooth=True)
        # lock icon inside
        canvas.create_rectangle(cx-4, cy-2, cx+4, cy+5,
                                 fill=BG, outline="")
        canvas.create_arc(cx-4, cy-7, cx+4, cy-1,
                          start=0, extent=180, style="arc",
                          outline=BG, width=2)

    # ── Entry focus effects ────────────────────────────────────────────────────

    def _on_entry_focus(self, event):
        if self._url_var.get() == "https://github.com/owner/repo":
            self._url_var.set("")

    def _on_entry_blur(self, event):
        if not self._url_var.get().strip():
            self._url_var.set("https://github.com/owner/repo")

    # ── Browse for output file ─────────────────────────────────────────────────

    def _browse_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("Text", "*.txt"), ("All", "*.*")],
            title="Save report as…",
        )
        if path:
            self._output_var.set(path)

    # ── Scan orchestration ─────────────────────────────────────────────────────

    def _start_scan(self):
        url = self._url_var.get().strip()
        if not url or url == "https://github.com/owner/repo":
            messagebox.showwarning("Missing URL",
                                   "Please enter a GitHub repository URL.")
            return

        self._reset_ui()
        self._scan_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        self._progress.start(12)
        self._status_var.set("Scanning…")
        self._log("=" * 64, "header")
        self._log(f"  Target : {url}", "header")
        self._log("=" * 64 + "\n", "header")

        token  = self._token_var.get().strip() or None
        output = self._output_var.get().strip() or None

        self._stop_event = threading.Event()
        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(url, token, output),
            daemon=True,
        )
        self._scan_thread.start()

    def _stop_scan(self):
        if self._stop_event:
            self._stop_event.set()
        self._status_var.set("Stopping…")

    def _scan_worker(self, repo_url: str, token, output_path):
        """Runs in background thread. Posts messages to self._queue."""
        def post(kind, data=None):
            self._queue.put((kind, data))

        def log(msg, tag="muted"):
            post("log", (msg, tag))

        try:
            # 1. Parse URL
            owner, repo = engine.parse_repo_url(repo_url)
            log(f"[1/4] Owner: {owner!r}  Repo: {repo!r}", "ok")

            if self._stop_event.is_set():
                post("stopped"); return

            # 2. Default branch
            branch = engine.get_default_branch(owner, repo, token)
            log(f"[2/4] Default branch: {branch!r}", "ok")

            if self._stop_event.is_set():
                post("stopped"); return

            # 3. File tree
            log("[3/4] Fetching file tree…", "muted")
            all_entries = engine.get_all_files(owner, repo, branch, token)
            supported   = [e for e in all_entries
                           if engine._is_supported(e["path"])]
            log(f"      {len(all_entries)} total files · "
                f"{len(supported)} match supported extensions\n", "ok")

            if self._stop_event.is_set():
                post("stopped"); return

            # 4. Fetch + scan
            log("[4/4] Scanning files…\n", "muted")
            report = engine.SecurityReport(repo_url=repo_url)

            for idx, entry in enumerate(supported, 1):
                if self._stop_event.is_set():
                    post("stopped"); return

                path = entry["path"]
                post("progress", (idx, len(supported), path))

                try:
                    repo_file = engine.fetch_file_content(
                        entry, owner, repo, token)
                except Exception as exc:
                    log(f"  [{idx:>3}/{len(supported)}] {path}  SKIP ({exc})", "warn")
                    continue

                if repo_file is None:
                    log(f"  [{idx:>3}/{len(supported)}] {path}  SKIP (too large / binary)", "warn")
                    continue

                issues = engine.scan_file_statically(repo_file)
                report.files_analysed += 1

                tag = "ok" if not issues else "warn"
                suffix = f"{len(issues)} issue(s)" if issues else "✓ clean"
                log(f"  [{idx:>3}/{len(supported)}] {path}  →  {suffix}", tag)

                if issues:
                    report.issues.extend(issues)

                import time; time.sleep(0.05)

            # 5. Generate report
            markdown = engine.generate_report(report)
            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(markdown)
                log(f"\n✅  Report saved to: {output_path}", "ok")

            post("done", (report, markdown))

        except Exception as exc:
            post("error", str(exc))

    # ── Queue polling (runs in main thread) ────────────────────────────────────

    def _poll_queue(self):
        try:
            while True:
                kind, data = self._queue.get_nowait()
                if kind == "log":
                    msg, tag = data
                    self._log(msg, tag)
                elif kind == "progress":
                    idx, total, path = data
                    self._status_var.set(
                        f"Scanning {idx}/{total}  ·  {os.path.basename(path)}")
                elif kind == "done":
                    report, markdown = data
                    self._on_scan_done(report, markdown)
                elif kind == "error":
                    self._on_scan_error(data)
                elif kind == "stopped":
                    self._on_scan_stopped()
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    # ── Scan lifecycle callbacks ───────────────────────────────────────────────

    def _on_scan_done(self, report: engine.SecurityReport, markdown: str):
        self._progress.stop()
        self._scan_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._export_btn.config(state="normal")
        self._report_text = markdown

        counts = {level: 0 for level in engine.RISK_ORDER}
        for issue in report.issues:
            counts[issue.risk_level] = counts.get(issue.risk_level, 0) + 1

        for level, var in self._count_vars.items():
            var.set(str(counts.get(level, 0)))
        self._files_var.set(str(report.files_analysed))

        self._issues = report.issues
        self._populate_tree(report.issues)

        # Raw report tab
        self._report_text_widget.config(state="normal")
        self._report_text_widget.delete("1.0", "end")
        self._report_text_widget.insert("end", markdown)
        self._report_text_widget.config(state="disabled")

        total = len(report.issues)
        self._status_var.set(
            f"Scan complete  ·  {report.files_analysed} files  ·  "
            f"{total} issue{'s' if total != 1 else ''} found"
        )
        self._log(f"\n{'=' * 64}", "header")
        self._log(f"  Scan complete — {report.files_analysed} files · "
                  f"{total} issues", "ok")
        self._log(f"{'=' * 64}", "header")

    def _on_scan_error(self, msg: str):
        self._progress.stop()
        self._scan_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._status_var.set(f"Error: {msg}")
        self._log(f"\n❌  {msg}", "error")
        messagebox.showerror("Scan Error", msg)

    def _on_scan_stopped(self):
        self._progress.stop()
        self._scan_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._status_var.set("Scan stopped by user")
        self._log("\n⏹  Scan stopped by user.", "warn")

    # ── Findings table helpers ─────────────────────────────────────────────────

    def _populate_tree(self, issues: list[engine.SecurityIssue], filter_level="All"):
        self._tree.delete(*self._tree.get_children())
        for issue in sorted(issues,
                            key=lambda i: engine.RISK_ORDER.get(i.risk_level, 99)):
            if filter_level != "All" and issue.risk_level != filter_level:
                continue
            emoji = RISK_EMOJI.get(issue.risk_level, "")
            self._tree.insert("", "end",
                values=(
                    f"{emoji} {issue.risk_level}",
                    issue.title,
                    issue.file_path,
                    issue.line_number,
                ),
                tags=(issue.risk_level,),
                # Store full issue object in a dict keyed by iid
            )
        # Map tree row iids back to issues for detail pane
        self._iid_to_issue: dict[str, engine.SecurityIssue] = {}
        for iid, issue in zip(self._tree.get_children(), [
            i for i in sorted(issues, key=lambda x: engine.RISK_ORDER.get(x.risk_level, 99))
            if filter_level == "All" or i.risk_level == filter_level
        ]):
            self._iid_to_issue[iid] = issue

    def _apply_filter(self, level: str):
        self._populate_tree(self._issues, level)

    def _on_finding_select(self, _event=None):
        sel = self._tree.selection()
        if not sel:
            return
        iid = sel[0]
        issue = self._iid_to_issue.get(iid)
        if not issue:
            return

        dt = self._detail_text
        dt.config(state="normal")
        dt.delete("1.0", "end")

        color = RISK_COLORS.get(issue.risk_level, TEXT)
        emoji = RISK_EMOJI.get(issue.risk_level, "")

        dt.insert("end", f"{emoji} {issue.risk_level}  ·  {issue.title}\n", "heading")
        dt.insert("end", f"📁 {issue.file_path}  ·  Line {issue.line_number}\n\n", "muted")
        dt.insert("end", "⚠  Why it's dangerous:\n", "heading")
        dt.insert("end", f"   {issue.description}\n\n", "danger")
        dt.insert("end", "🔎  Offending code:\n", "heading")
        dt.insert("end", f"   {issue.code_snippet}\n\n", "code")
        dt.insert("end", "✅  Recommended fix:\n", "heading")
        dt.insert("end", f"   {issue.fix}\n", "fix")

        dt.config(state="disabled")

    # ── Log helpers ────────────────────────────────────────────────────────────

    def _log(self, msg: str, tag: str = "muted"):
        self._log_text.config(state="normal")
        self._log_text.insert("end", msg + "\n", tag)
        self._log_text.see("end")
        self._log_text.config(state="disabled")

    # ── Reset UI for new scan ──────────────────────────────────────────────────

    def _reset_ui(self):
        for var in self._count_vars.values():
            var.set("—")
        self._files_var.set("—")
        self._tree.delete(*self._tree.get_children())
        self._issues = []
        self._report_text = ""
        self._iid_to_issue = {}

        self._detail_text.config(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.config(state="disabled")

        self._report_text_widget.config(state="normal")
        self._report_text_widget.delete("1.0", "end")
        self._report_text_widget.config(state="disabled")

        self._log_text.config(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.config(state="disabled")

        self._export_btn.config(state="disabled")

    # ── Export ─────────────────────────────────────────────────────────────────

    def _export_report(self):
        path = self._output_var.get().strip()
        if not path:
            path = filedialog.asksaveasfilename(
                defaultextension=".md",
                filetypes=[("Markdown", "*.md"), ("Text", "*.txt"), ("All", "*.*")],
                title="Save report as…",
            )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._report_text)
            messagebox.showinfo("Exported", f"Report saved to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Export Error", str(exc))


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    app = SecurityAgentApp()

    # Try to set a window icon (works on Windows with .ico)
    icon_path = os.path.join(_BASE, "assets", "icon.ico")
    if os.path.exists(icon_path):
        try:
            app.iconbitmap(icon_path)
        except Exception:
            pass

    app.mainloop()


if __name__ == "__main__":
    main()
