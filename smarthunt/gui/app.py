"""The SmartHunt main window."""

from __future__ import annotations

import os
import queue
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

from .. import __version__, ai, report
from ..engine import (DEFAULT_ENABLED, MODE_DOMAIN, MODE_WILDCARD, STAGES,
                      STAGE_TITLES, ScanConfig, Scanner, normalize_target)
from ..tools import CATEGORIES, REGISTRY, detect_tools
from . import theme
from .widgets import (ListPane, LogPane, ModeSelector, ResultTable, StatCard,
                      dark_check)

STAGE_ICONS = {"pending": "○", "running": "◐", "done": "●", "skipped": "◌"}
STAGE_COLORS = {"pending": theme.MUTED, "running": theme.ACCENT,
                "done": theme.OK, "skipped": theme.MUTED}


class SmartHuntApp(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.title(f"SmartHunt v{__version__} — Bug Hunting Recon Suite")
        # Tk's baseline is 1.333 pixels per point. A HiDPI display raises that,
        # so every point-sized font comes out bigger — and any measurement given
        # in raw pixels has to follow, or the sidebar clips the labels it was
        # sized around.
        self.ui_scale = max(1.0, float(self.tk.call("tk", "scaling")) / 1.3333)
        self.geometry(f"{int(1500 * self.ui_scale)}x{int(920 * self.ui_scale)}")
        self.minsize(int(1120 * self.ui_scale), int(720 * self.ui_scale))
        theme.apply(self)

        self.inventory = detect_tools()
        self.scanner: Scanner | None = None
        self.results = None
        self.event_queue: queue.Queue = queue.Queue()
        self.stage_labels: dict[str, ttk.Label] = {}
        self.stage_vars: dict[str, tk.BooleanVar] = {}

        self._build_ui()
        self._on_mode_change()
        preset = os.environ.get("SMARTHUNT_TARGET", "").strip()
        if preset:
            self.target_var.set(preset)
        self.after(100, self._drain_events)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ #
    # Layout
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        self._build_header()

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        body.columnconfigure(0, minsize=int(368 * self.ui_scale))
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_sidebar(body)
        self._build_tabs(body)
        self.after(300, self._animate)
        self._build_statusbar()

    def _build_header(self):
        head = ttk.Frame(self)
        head.pack(fill="x", padx=12, pady=(10, 6))

        left = ttk.Frame(head)
        left.pack(side="left")
        self.logo_label = ttk.Label(left, text="▚ SmartHunt", style="Title.TLabel")
        self.logo_label.pack(side="left")
        ttk.Label(left, text="  bug-hunting recon suite", style="Muted.TLabel").pack(side="left", pady=(6, 0))

        right = ttk.Frame(head)
        right.pack(side="right")
        found = len(self.inventory.available)
        self.arsenal_label = ttk.Label(
            right, text=f"⚙ {found}/{len(REGISTRY)} external tools", style="Muted.TLabel")
        self.arsenal_label.pack(side="left", padx=(0, 10))
        ttk.Button(right, text="Re-scan tools", command=self._rescan_tools).pack(side="left", padx=3)
        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=12)

    # --- sidebar ---------------------------------------------------------
    def _build_sidebar(self, parent):
        outer = ttk.Frame(parent)
        outer.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=6)

        canvas = tk.Canvas(outer, bg=theme.BG, highlightthickness=0,
                           width=int(350 * self.ui_scale))
        scroll = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        side = ttk.Frame(canvas)
        side.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        window = canvas.create_window((0, 0), window=side, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(window, width=e.width))
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))
        canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
        canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))

        # --- Target ------------------------------------------------------
        target_box = ttk.Labelframe(side, text=" Target ", padding=10)
        target_box.pack(fill="x", pady=(0, 8))

        self.mode_var = tk.StringVar(value=MODE_DOMAIN)
        ModeSelector(target_box, self.mode_var, [
            (MODE_DOMAIN, "Single Domain   —   example.com",
             "Deep-dive one host: JavaScript, endpoints, parameters, content, vulns."),
            (MODE_WILDCARD, "Wildcard   —   *.example.com",
             "Full recon: every subdomain source and tool, then go deep on what's live."),
        ], command=self._on_mode_change).pack(fill="x", pady=(0, 4))

        self.target_var = tk.StringVar()
        entry = ttk.Entry(target_box, textvariable=self.target_var, font=("Consolas", 11))
        entry.pack(fill="x")
        entry.bind("<Return>", lambda e: self._start_scan())
        entry.focus_set()
        self.target_hint = ttk.Label(target_box, text="", style="Muted.TLabel")
        self.target_hint.pack(anchor="w", pady=(4, 0))
        self.target_var.trace_add("write", lambda *_: self._update_hint())

        # --- Controls -----------------------------------------------------
        controls = ttk.Frame(side)
        controls.pack(fill="x", pady=(0, 8))
        self.start_btn = ttk.Button(controls, text="▶  START", style="Start.TButton",
                                    command=self._start_scan)
        self.start_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.stop_btn = ttk.Button(controls, text="■  STOP", style="Stop.TButton",
                                   command=self._stop_scan, state="disabled")
        self.stop_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.pause_btn = ttk.Button(controls, text="PAUSE", width=7,
                                    command=self._toggle_pause, state="disabled")
        self.pause_btn.pack(side="left")

        # --- Stages -------------------------------------------------------
        self.stage_box = ttk.Labelframe(side, text=" Modules ", padding=10)
        self.stage_box.pack(fill="x", pady=(0, 8))
        for key, title, modes in STAGES:
            row = ttk.Frame(self.stage_box)
            row.pack(fill="x", pady=1)
            var = tk.BooleanVar(value=True)
            self.stage_vars[key] = var
            chk = dark_check(row, title, var)
            chk.pack(side="left")
            status = ttk.Label(row, text=STAGE_ICONS["pending"], style="Muted.TLabel")
            status.pack(side="right")
            self.stage_labels[key] = status
            row.stage_key = key
            row.checkbox = chk

        toggles = ttk.Frame(self.stage_box)
        toggles.pack(fill="x", pady=(6, 0))
        ttk.Button(toggles, text="All", width=6,
                   command=lambda: self._set_all_stages(True)).pack(side="left", padx=2)
        ttk.Button(toggles, text="None", width=6,
                   command=lambda: self._set_all_stages(False)).pack(side="left", padx=2)
        ttk.Button(toggles, text="Defaults", width=9,
                   command=self._reset_stages).pack(side="left", padx=2)

        # --- Options -------------------------------------------------------
        opts = ttk.Labelframe(side, text=" Options ", padding=10)
        opts.pack(fill="x", pady=(0, 8))

        self.threads_var = tk.IntVar(value=40)
        self.depth_var = tk.IntVar(value=2)
        self.pages_var = tk.IntVar(value=300)
        self.jsfiles_var = tk.IntVar(value=400)
        self.bruteforce_var = tk.BooleanVar(value=True)
        self.exhaustive_var = tk.BooleanVar(value=False)
        self.subs_in_urls_var = tk.BooleanVar(value=True)
        self.severity_var = tk.StringVar(value="low,medium,high,critical")
        self.ports_var = tk.StringVar(value="")

        self._spin(opts, "Threads", self.threads_var, 5, 500, 5)
        self._spin(opts, "Crawl depth", self.depth_var, 1, 5, 1)
        self._spin(opts, "Max pages to crawl", self.pages_var, 20, 5000, 20)
        self._spin(opts, "Max JS files", self.jsfiles_var, 20, 5000, 20)

        row = ttk.Frame(opts)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Ports", width=18, style="Muted.TLabel").pack(side="left")
        ttk.Entry(row, textvariable=self.ports_var).pack(side="left", fill="x", expand=True)
        ttk.Label(opts, text="  blank = built-in top ports; e.g. 80,443,8080",
                  style="Muted.TLabel").pack(anchor="w")

        row = ttk.Frame(opts)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="nuclei severity", width=18, style="Muted.TLabel").pack(side="left")
        ttk.Combobox(row, textvariable=self.severity_var, state="readonly", width=22,
                     values=["info,low,medium,high,critical", "low,medium,high,critical",
                             "medium,high,critical", "high,critical",
                             "critical"]).pack(side="left", fill="x", expand=True)

        dark_check(opts, "DNS bruteforce subdomains",
                   self.bruteforce_var).pack(anchor="w", fill="x", pady=(5, 0))
        dark_check(opts, "Include subdomains in URL collection",
                   self.subs_in_urls_var).pack(anchor="w", fill="x")
        dark_check(opts, "EXHAUSTIVE — loop until nothing new is found",
                   self.exhaustive_var).pack(anchor="w", fill="x")

        # --- Session (authenticated testing) ---------------------------------
        sess = ttk.Labelframe(side, text=" Session — authenticated testing ",
                              padding=10)
        sess.pack(fill="x", pady=(0, 10))
        ttk.Label(sess, wraplength=int(300 * self.ui_scale), style="Muted.TLabel",
                  text=("Paste a session you already have: a Cookie value, a bearer "
                        "token, or a raw header block from Burp/devtools. A second "
                        "account you also control enables IDOR proof.")
                  ).pack(anchor="w", pady=(0, 6))

        self.auth_cookie_var = tk.StringVar()
        self.auth_bearer_var = tk.StringVar()
        self.auth_check_url_var = tk.StringVar()
        self.auth_check_text_var = tk.StringVar()
        self.victim_cookie_var = tk.StringVar()
        self.victim_bearer_var = tk.StringVar()

        def labelled(parent_frame, text, var, width=26):
            row = ttk.Frame(parent_frame)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=text, width=13, style="Muted.TLabel").pack(side="left")
            ttk.Entry(row, textvariable=var, width=width).pack(side="left", fill="x",
                                                              expand=True)

        ttk.Label(sess, text="ACCOUNT A — used for all testing",
                  style="Head.TLabel").pack(anchor="w", pady=(4, 2))
        labelled(sess, "Cookie", self.auth_cookie_var)
        labelled(sess, "Bearer token", self.auth_bearer_var)
        ttk.Label(sess, text="or paste a header block:", style="Muted.TLabel").pack(anchor="w")
        self.auth_headers_text = tk.Text(
            sess, height=3, bg=theme.BG_DEEP, fg=theme.ACCENT, relief="flat",
            font=theme.FONT_MONO, insertbackground=theme.ACCENT,
            highlightthickness=1, highlightbackground=theme.LINE)
        self.auth_headers_text.pack(fill="x", pady=(2, 6))

        ttk.Label(sess, text="SESSION CHECK — proves it is live",
                  style="Head.TLabel").pack(anchor="w", pady=(4, 2))
        labelled(sess, "URL", self.auth_check_url_var)
        labelled(sess, "Text when in", self.auth_check_text_var)

        ttk.Label(sess, text="ACCOUNT B — optional, enables IDOR",
                  style="Head.TLabel").pack(anchor="w", pady=(6, 2))
        labelled(sess, "Cookie", self.victim_cookie_var)
        labelled(sess, "Bearer token", self.victim_bearer_var)
        ttk.Label(sess, wraplength=int(300 * self.ui_scale), style="Muted.TLabel",
                  text=("Both accounts must be yours. SmartHunt only reads objects "
                        "Account B has confirmed it owns.")).pack(anchor="w", pady=(4, 0))

        # --- AI assist --------------------------------------------------------
        ai_box = ttk.Labelframe(side, text=" AI assist ", padding=10)
        ai_box.pack(fill="x", pady=(0, 8))
        self.ai_enabled_var = tk.BooleanVar(value=False)
        self.ai_tuning_var = tk.BooleanVar(value=True)
        self.ai_report_var = tk.BooleanVar(value=True)
        self.ai_model_var = tk.StringVar(value="")

        status = ai.detect()
        ttk.Label(ai_box, wraplength=int(300 * self.ui_scale),
                  style="Head.TLabel" if status["available"] else "Muted.TLabel",
                  text=("● " if status["available"] else "○ ") + status["detail"]
                  ).pack(anchor="w", pady=(0, 6))

        dark_check(ai_box, "Enable AI assist", self.ai_enabled_var).pack(anchor="w", fill="x")
        dark_check(ai_box, "  retune the scan while it runs",
                   self.ai_tuning_var).pack(anchor="w", fill="x")
        dark_check(ai_box, "  write the report from the evidence",
                   self.ai_report_var).pack(anchor="w", fill="x")
        labelled(ai_box, "Model", self.ai_model_var)
        ttk.Label(ai_box, wraplength=int(300 * self.ui_scale), style="Muted.TLabel",
                  text=("It tunes settings and writes prose. It never decides "
                        "whether something is a bug — every sentence is checked "
                        "against the captured evidence and dropped if it is not "
                        "backed by it. Turning this on sends scan metadata and "
                        "the redacted evidence for the one finding to Anthropic.")
                  ).pack(anchor="w", pady=(4, 0))

        # --- Wordlists ------------------------------------------------------
        wl = ttk.Labelframe(side, text=" Wordlists (optional) ", padding=10)
        wl.pack(fill="x", pady=(0, 8))
        self.sub_wordlist_var = tk.StringVar()
        self.content_wordlist_var = tk.StringVar()
        self._file_row(wl, "Subdomains", self.sub_wordlist_var)
        self._file_row(wl, "Content paths", self.content_wordlist_var)
        ttk.Label(wl, text="Blank uses the built-in lists.",
                  style="Muted.TLabel").pack(anchor="w", pady=(3, 0))

        # --- Output ----------------------------------------------------------
        out = ttk.Labelframe(side, text=" Output ", padding=10)
        out.pack(fill="x", pady=(0, 8))
        self.outdir_var = tk.StringVar(value=os.path.join(os.getcwd(), "smarthunt-results"))
        self._file_row(out, "Directory", self.outdir_var, directory=True)
        btns = ttk.Frame(out)
        btns.pack(fill="x", pady=(6, 0))
        self.export_btn = ttk.Button(btns, text="Export all", style="Accent.TButton",
                                     command=self._export, state="disabled")
        self.export_btn.pack(side="left", expand=True, fill="x", padx=(0, 3))
        self.open_btn = ttk.Button(btns, text="Open report", command=self._open_report,
                                   state="disabled")
        self.open_btn.pack(side="left", expand=True, fill="x")

    def _spin(self, parent, label, var, lo, hi, step):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text=label, width=18, style="Muted.TLabel").pack(side="left")
        ttk.Spinbox(row, from_=lo, to=hi, increment=step, textvariable=var,
                    width=10).pack(side="left", fill="x", expand=True)

    def _file_row(self, parent, label, var, directory=False):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text=label, width=13, style="Muted.TLabel").pack(side="left")
        ttk.Entry(row, textvariable=var).pack(side="left", fill="x", expand=True, padx=(0, 4))

        def browse():
            path = (filedialog.askdirectory(title=f"Select {label}") if directory
                    else filedialog.askopenfilename(title=f"Select {label} wordlist"))
            if path:
                var.set(path)

        ttk.Button(row, text="…", width=3, command=browse).pack(side="left")

    # --- tabs -------------------------------------------------------------
    # --- animation ---------------------------------------------------------
    SPINNER = ("◐", "◓", "◑", "◒")

    def _animate(self):
        """Drive the running-stage spinner and the scanning pulse.

        Tk has no animation loop, so this reschedules itself on the event loop.
        It only redraws while a scan is running, and stops touching widgets the
        moment one is not, so an idle window costs nothing.
        """
        self._tick = getattr(self, "_tick", 0) + 1
        if self.scanner and self.scanner.running:
            glyph = self.SPINNER[self._tick % len(self.SPINNER)]
            # Only the stage currently marked running spins; the others keep
            # their pending/done glyph.
            for key in getattr(self, "_running_stages", set()):
                label = self.stage_labels.get(key)
                if label is not None:
                    label.config(text=glyph, foreground=theme.ACCENT)
            self.logo_label.config(
                foreground=theme.ACCENT if self._tick % 2 else theme.MUTED)
        elif getattr(self, "_was_running", False):
            self.logo_label.config(foreground=theme.ACCENT)
        self._was_running = bool(self.scanner and self.scanner.running)
        self.after(180, self._animate)

    def _count_up(self, card, target, step=0):
        """Ease a stat tile up to its value instead of snapping to it."""
        try:
            value = int(target)
        except (TypeError, ValueError):
            card.set(target)
            return
        frames = 12
        if step > frames or value == 0:
            card.set(value)
            return
        # ease-out cubic: quick, then settling — reads as counting up
        card.set(int(value * (1 - (1 - step / frames) ** 3)))
        self.after(28, lambda: self._count_up(card, value, step + 1))

    def _render_report(self, results):
        """Show the triaged finding, mirroring the browser UI's Report pane."""
        report = getattr(results, "report", None) or {}
        kind = report.get("kind")
        self._report_markdown = report.get("markdown", "")

        label = {
            "report": f"[!] REPORTABLE  severity={report.get('severity', '?').upper()}",
            "evidence_needed": "[~] EVIDENCE NEEDED — not yet reportable",
            "none": "[ ] No reportable vulnerability found with the current evidence",
        }.get(kind, "[ ] No report")
        considered = report.get("considered", 0)
        dropped = report.get("dropped", 0)
        if considered:
            label += f"   ({considered} findings considered, {dropped} not standalone)"
        if report.get("ai_written"):
            label += "   · written by AI from the captured evidence"
        self.report_status.set(label)

        self.report_text.configure(state="normal")
        self.report_text.delete("1.0", "end")
        if not self._report_markdown:
            self.report_text.insert("1.0", "No reportable vulnerability found "
                                           "with the current evidence.\n")
        else:
            for line in self._report_markdown.split("\n"):
                stripped = line.strip()
                if stripped.startswith("# "):
                    self.report_text.insert("end", stripped[2:] + "\n", "h1")
                elif stripped.startswith("## "):
                    self.report_text.insert("end", "\n" + stripped[3:] + "\n", "h2")
                elif stripped.startswith("```"):
                    continue
                elif stripped.startswith(("curl ", "GET ", "POST ", "HTTP/")):
                    self.report_text.insert("end", line + "\n", "code")
                elif stripped.startswith("**Severity:**"):
                    self.report_text.insert("end", stripped.replace("**", "") + "\n", "crit")
                else:
                    self.report_text.insert("end", line.replace("**", "") + "\n")
        self.report_text.configure(state="disabled")
        if kind in ("report", "evidence_needed"):
            self.tabs.select(0)

    def _copy_report(self):
        text = getattr(self, "_report_markdown", "")
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_var.set("Report copied to clipboard as Markdown")

    def _build_tabs(self, parent):
        right = ttk.Frame(parent)
        right.grid(row=0, column=1, sticky="nsew", pady=6)
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        prog = ttk.Frame(right)
        prog.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.stage_text = tk.StringVar(value="Idle — enter a target and press START")
        ttk.Label(prog, textvariable=self.stage_text, style="Head.TLabel").pack(anchor="w")
        self.progress = ttk.Progressbar(prog, mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(4, 0))

        self.tabs = ttk.Notebook(right)
        self.tabs.grid(row=1, column=0, sticky="nsew")

        # Report — the triaged single finding, and the default landing tab
        report_frame = ttk.Frame(self.tabs)
        self.tabs.add(report_frame, text=" ▓ REPORT ")
        report_frame.rowconfigure(1, weight=1)
        report_frame.columnconfigure(0, weight=1)

        report_bar = ttk.Frame(report_frame)
        report_bar.grid(row=0, column=0, sticky="ew", padx=6, pady=(6, 4))
        self.report_status = tk.StringVar(value="[ awaiting target ]")
        ttk.Label(report_bar, textvariable=self.report_status,
                  style="Head.TLabel").pack(side="left")
        ttk.Button(report_bar, text="Copy Markdown",
                   command=self._copy_report).pack(side="right")

        self.report_text = tk.Text(
            report_frame, wrap="word", bg=theme.PANEL, fg=theme.FG,
            insertbackground=theme.ACCENT, relief="flat", padx=14, pady=12,
            font=theme.FONT_MONO, highlightthickness=1,
            highlightbackground=theme.LINE)
        self.report_text.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        report_scroll = ttk.Scrollbar(report_frame, orient="vertical",
                                      command=self.report_text.yview)
        report_scroll.grid(row=1, column=1, sticky="ns", pady=(0, 6))
        self.report_text.configure(yscrollcommand=report_scroll.set)
        for tag, colour, font in (
                ("h1", theme.ACCENT, (theme.FONT_MONO[0], 14, "bold")),
                ("h2", theme.ACCENT, (theme.FONT_MONO[0], 10, "bold")),
                ("code", theme.MUTED, theme.FONT_MONO),
                ("crit", theme.ERR, (theme.FONT_MONO[0], 10, "bold"))):
            self.report_text.tag_configure(tag, foreground=colour, font=font)
        self.report_text.insert("1.0",
                                "Run a scan — the single strongest reportable finding "
                                "lands here,\nwith raw request/response evidence and "
                                "steps to reproduce.\n")
        self.report_text.configure(state="disabled")

        # Dashboard
        dash = ttk.Frame(self.tabs)
        self.tabs.add(dash, text=" Dashboard ")
        self._build_dashboard(dash)

        # Result tabs
        self.tbl_findings = ResultTable(
            self.tabs, ["Severity", "Host", "Finding", "Detail", "Source"],
            widths=[85, 200, 250, 460, 90])
        self.tabs.add(self.tbl_findings, text=" Findings ")

        self.tbl_secrets = ResultTable(
            self.tabs, ["Severity", "Type", "Value", "Source file"],
            widths=[85, 190, 300, 470])
        self.tabs.add(self.tbl_secrets, text=" Secrets ")

        self.tbl_hosts = ResultTable(
            self.tabs, ["Host", "Status", "Title", "Tech", "Ports", "IPs", "URL"],
            widths=[210, 60, 230, 180, 110, 140, 230])
        self.tabs.add(self.tbl_hosts, text=" Hosts ")

        self.lst_subdomains = ListPane(self.tabs)
        self.tabs.add(self.lst_subdomains, text=" Subdomains ")

        self.lst_urls = ListPane(self.tabs)
        self.tabs.add(self.lst_urls, text=" URLs ")

        self.lst_js = ListPane(self.tabs)
        self.tabs.add(self.lst_js, text=" JS ")

        self.lst_endpoints = ListPane(self.tabs)
        self.tabs.add(self.lst_endpoints, text=" Endpoints ")

        self.lst_params = ListPane(self.tabs)
        self.tabs.add(self.lst_params, text=" Params ")

        self.tbl_content = ResultTable(
            self.tabs, ["URL", "Status", "Length", "Type"], widths=[620, 80, 100, 200])
        self.tabs.add(self.tbl_content, text=" Content ")

        self.log_pane = LogPane(self.tabs)
        self.tabs.add(self.log_pane, text=" Log ")

        self.arsenal = ttk.Frame(self.tabs)
        self.tabs.add(self.arsenal, text=" Arsenal ")
        self._build_arsenal()

    def _build_dashboard(self, parent):
        wrap = ttk.Frame(parent, padding=14)
        wrap.pack(fill="both", expand=True)

        ttk.Label(wrap, text="Scan summary", style="Head.TLabel").pack(anchor="w")
        cards = ttk.Frame(wrap)
        cards.pack(fill="x", pady=(8, 16))
        self.cards: dict[str, StatCard] = {}
        for label in ["Subdomains", "Live hosts", "URLs", "JS files", "Endpoints",
                      "Parameters", "Secrets", "Findings", "Critical/High"]:
            card = StatCard(cards, label)
            card.pack(side="left", padx=(0, 8))
            self.cards[label] = card

        ttk.Separator(wrap, orient="horizontal").pack(fill="x", pady=6)

        cols = ttk.Frame(wrap)
        cols.pack(fill="both", expand=True, pady=(10, 0))

        left = ttk.Frame(cols)
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))
        ttk.Label(left, text="Pipeline", style="Head.TLabel").pack(anchor="w", pady=(0, 6))
        self.pipeline_frame = ttk.Frame(left)
        self.pipeline_frame.pack(fill="x")
        self.pipeline_labels: dict[str, ttk.Label] = {}
        for key, title, _ in STAGES:
            lbl = ttk.Label(self.pipeline_frame, text=f"  {STAGE_ICONS['pending']}  {title}",
                            style="Muted.TLabel")
            lbl.pack(anchor="w", pady=1)
            self.pipeline_labels[key] = lbl

        right = ttk.Frame(cols)
        right.pack(side="left", fill="both", expand=True)
        ttk.Label(right, text="Top findings by severity", style="Head.TLabel").pack(anchor="w", pady=(0, 6))
        self.sev_frame = ttk.Frame(right)
        self.sev_frame.pack(fill="x")
        self.sev_labels: dict[str, ttk.Label] = {}
        for sev in ["critical", "high", "medium", "low", "info"]:
            lbl = tk.Label(self.sev_frame, text=f"{sev.upper():<10} 0", bg=theme.BG,
                           fg=theme.SEVERITY[sev], font=("Consolas", 11, "bold"), anchor="w")
            lbl.pack(anchor="w", fill="x", pady=1)
            self.sev_labels[sev] = lbl

        ttk.Label(right, text="\nAuthorized testing only — scan targets you own or have "
                             "written permission to test.", style="Muted.TLabel",
                  wraplength=int(380 * self.ui_scale), justify="left").pack(anchor="w", pady=(14, 0))

    def _build_arsenal(self):
        canvas = tk.Canvas(self.arsenal, bg=theme.BG, highlightthickness=0)
        scroll = ttk.Scrollbar(self.arsenal, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        window = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(window, width=e.width))
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scroll.pack(side="right", fill="y")
        self._arsenal_inner = inner
        self._render_arsenal()

    def _render_arsenal(self):
        for child in self._arsenal_inner.winfo_children():
            child.destroy()
        inner = self._arsenal_inner

        header = ttk.Frame(inner)
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text=self.inventory.summary(), style="Head.TLabel",
                  wraplength=int(900 * self.ui_scale), justify="left").pack(anchor="w")
        ttk.Label(header, text="Every tool below is optional — SmartHunt falls back to built-in "
                               "pure-Python modules for anything that is missing. Install more "
                               "tools for deeper coverage.",
                  style="Muted.TLabel", wraplength=int(900 * self.ui_scale), justify="left").pack(anchor="w", pady=(4, 0))

        for category in CATEGORIES:
            tools = [t for t in REGISTRY if t.category == category]
            if not tools:
                continue
            box = ttk.Labelframe(inner, text=f" {category} ", padding=8)
            box.pack(fill="x", pady=5)
            for tool in tools:
                row = ttk.Frame(box)
                row.pack(fill="x", pady=1)
                installed = self.inventory.has(tool.name)
                mark = tk.Label(row, text="●" if installed else "○", bg=theme.BG,
                                fg=theme.OK if installed else theme.MUTED, font=("Segoe UI", 11))
                mark.pack(side="left", padx=(0, 6))
                name = tk.Label(row, text=f"{tool.name:<20}", bg=theme.BG,
                                fg=theme.FG if installed else theme.MUTED,
                                font=("Consolas", 10, "bold" if installed else "normal"),
                                anchor="w", width=20)
                name.pack(side="left")
                tk.Label(row, text=tool.description, bg=theme.BG, fg=theme.MUTED,
                         font=("Segoe UI", 9), anchor="w").pack(side="left", fill="x", expand=True)
                if not installed:
                    tk.Label(row, text=tool.install, bg=theme.BG, fg=theme.DIM,
                             font=("Consolas", 8), anchor="e").pack(side="right")

    def _build_statusbar(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", side="bottom", padx=12, pady=(0, 8))
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.status_var, style="Muted.TLabel").pack(side="left")
        self.elapsed_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.elapsed_var, style="Muted.TLabel").pack(side="right")

    # ------------------------------------------------------------------ #
    # Behaviour
    # ------------------------------------------------------------------ #
    def _update_hint(self):
        raw = self.target_var.get().strip()
        if not raw:
            self.target_hint.config(text="")
            return
        try:
            mode, apex = normalize_target(raw)
        except ValueError as exc:
            self.target_hint.config(text=f"✗ {exc}", foreground=theme.ERR)
            return
        if raw.startswith("*.") or raw.startswith("."):
            self.mode_var.set(MODE_WILDCARD)
            self._on_mode_change()
        self.target_hint.config(text=f"✓ scope: {apex}", foreground=theme.OK)

    def _on_mode_change(self):
        mode = self.mode_var.get()
        for child in self.stage_box.winfo_children():
            key = getattr(child, "stage_key", None)
            if key is None:
                continue
            applies = mode in dict((k, m) for k, _, m in STAGES)[key]
            child.checkbox.configure(state="normal" if applies else "disabled")
            if not applies:
                self.stage_vars[key].set(False)
            elif key in DEFAULT_ENABLED[mode]:
                self.stage_vars[key].set(True)
        placeholder = "example.com" if mode == MODE_DOMAIN else "*.example.com"
        if not self.target_var.get().strip():
            self.target_hint.config(text=f"e.g. {placeholder}", foreground=theme.MUTED)

    def _set_all_stages(self, value):
        mode = self.mode_var.get()
        for key, _, modes in STAGES:
            if mode in modes:
                self.stage_vars[key].set(value)

    def _reset_stages(self):
        mode = self.mode_var.get()
        for key, _, modes in STAGES:
            self.stage_vars[key].set(mode in modes and key in DEFAULT_ENABLED[mode])

    def _rescan_tools(self):
        self.inventory = detect_tools()
        self.arsenal_label.config(
            text=f"⚙ {len(self.inventory.available)}/{len(REGISTRY)} external tools")
        self._render_arsenal()
        self.status_var.set(self.inventory.summary())

    # --- scan lifecycle ---------------------------------------------------
    def _start_scan(self):
        if self.scanner and self.scanner.running:
            return
        raw = self.target_var.get().strip()
        try:
            detected_mode, apex = normalize_target(raw)
        except ValueError as exc:
            messagebox.showerror("Invalid target", str(exc))
            return

        mode = self.mode_var.get()
        if detected_mode == MODE_WILDCARD and mode == MODE_DOMAIN:
            mode = MODE_WILDCARD
            self.mode_var.set(mode)

        stages = {k for k, _, modes in STAGES if mode in modes and self.stage_vars[k].get()}
        if not stages:
            messagebox.showwarning("No modules", "Enable at least one module before starting.")
            return

        scope = f"*.{apex}" if mode == MODE_WILDCARD else apex
        if not messagebox.askyesno(
                "Confirm authorization",
                f"Target scope:  {scope}\nMode:  {mode}\n"
                f"Modules:  {len(stages)}\n\n"
                "This sends live traffic to the target.\n"
                "Only continue if you own this target or have written "
                "authorization to test it (e.g. an in-scope bug bounty program).\n\n"
                "Do you confirm you are authorized?"):
            return

        ports = []
        for chunk in self.ports_var.get().replace(" ", "").split(","):
            if chunk.isdigit():
                ports.append(int(chunk))

        config = ScanConfig(
            target=apex, mode=mode, enabled_stages=stages,
            threads=max(1, self.threads_var.get()),
            include_subdomains=self.subs_in_urls_var.get(),
            bruteforce_subdomains=self.bruteforce_var.get(),
            exhaustive=self.exhaustive_var.get(),
            auth_cookies=self.auth_cookie_var.get().strip(),
            auth_bearer=self.auth_bearer_var.get().strip(),
            auth_headers=self.auth_headers_text.get("1.0", "end").strip(),
            auth_check_url=self.auth_check_url_var.get().strip(),
            auth_check_marker=self.auth_check_text_var.get().strip(),
            victim_cookies=self.victim_cookie_var.get().strip(),
            victim_bearer=self.victim_bearer_var.get().strip(),
            crawl_depth=self.depth_var.get(), max_pages=self.pages_var.get(),
            max_js_files=self.jsfiles_var.get(), ports=ports,
            subdomain_wordlist=self.sub_wordlist_var.get().strip(),
            content_wordlist=self.content_wordlist_var.get().strip(),
            nuclei_severity=self.severity_var.get(),
            output_dir=self.outdir_var.get().strip() or os.getcwd(),
            authorized=True,
            ai_enabled=self.ai_enabled_var.get(),
            ai_model=self.ai_model_var.get().strip(),
            ai_advice=self.ai_tuning_var.get(),
            ai_report=self.ai_report_var.get(),
        )

        self._reset_views()
        self.scanner = Scanner(
            config, inventory=self.inventory,
            on_log=lambda lvl, msg: self.event_queue.put(("log", (lvl, msg))),
            on_stage=lambda key, state: self.event_queue.put(("stage", (key, state))),
            on_progress=lambda done, total: self.event_queue.put(("progress", (done, total))),
            on_done=lambda res, err: self.event_queue.put(("done", (res, err))),
        )
        self._scan_start_time = time.time()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.pause_btn.config(state="normal", text="PAUSE")
        self.export_btn.config(state="disabled")
        self.open_btn.config(state="disabled")
        self.progress.config(value=0)
        self.status_var.set(f"Scanning {scope} …")
        self.tabs.select(0)
        self.scanner.start()
        self._tick_elapsed()

    def _stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.status_var.set("Stopping — finishing current module …")
            self.stop_btn.config(state="disabled")

    def _toggle_pause(self):
        if not self.scanner or not self.scanner.running:
            return
        if self.scanner.pause_event.is_set():
            self.scanner.resume()
            self.pause_btn.config(text="PAUSE")
            self.status_var.set("Resumed")
        else:
            self.scanner.pause()
            self.pause_btn.config(text="RESUME")
            self.status_var.set("Paused — will stop at the next module boundary")

    def _tick_elapsed(self):
        if self.scanner and self.scanner.running:
            self.elapsed_var.set(f"elapsed {time.time() - self._scan_start_time:.0f}s")
            self.after(1000, self._tick_elapsed)

    def _reset_views(self):
        for table in (self.tbl_findings, self.tbl_secrets, self.tbl_hosts, self.tbl_content):
            table.clear()
        for pane in (self.lst_subdomains, self.lst_urls, self.lst_js,
                     self.lst_endpoints, self.lst_params):
            pane.set_items([])
        for card in self.cards.values():
            card.set(0)
        for sev, lbl in self.sev_labels.items():
            lbl.config(text=f"{sev.upper():<10} 0")
        for key in self.stage_labels:
            self._set_stage_state(key, "pending")
        self.log_pane.clear()

    def _set_stage_state(self, key, state):
        icon = STAGE_ICONS.get(state, "○")
        color = STAGE_COLORS.get(state, theme.MUTED)
        # The animation loop spins whatever is in here and leaves the rest alone.
        running = getattr(self, "_running_stages", None)
        if running is None:
            running = self._running_stages = set()
        running.add(key) if state == "running" else running.discard(key)
        if key in self.stage_labels:
            self.stage_labels[key].config(text=icon, foreground=color)
        if key in self.pipeline_labels:
            self.pipeline_labels[key].config(text=f"  {icon}  {STAGE_TITLES[key]}",
                                             foreground=color)

    # --- event pump -------------------------------------------------------
    def _drain_events(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "log":
                    level, message = payload
                    self.log_pane.append(level, message, time.strftime("%H:%M:%S"))
                elif kind == "stage":
                    key, state = payload
                    self._set_stage_state(key, state)
                    if state == "running":
                        self.stage_text.set(f"Running: {STAGE_TITLES[key]}")
                elif kind == "progress":
                    done, total = payload
                    self.progress.config(value=(done / total * 100) if total else 0)
                elif kind == "done":
                    self._on_scan_done(*payload)
        except queue.Empty:
            pass
        self.after(120, self._drain_events)

    def _on_scan_done(self, results, error):
        self.results = results
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.pause_btn.config(state="disabled", text="PAUSE")
        self.export_btn.config(state="normal")
        self.progress.config(value=100)
        self.elapsed_var.set(f"finished in {results.duration:.1f}s")

        stats = results.stats()
        for label, card in self.cards.items():
            self._count_up(card, stats.get(label, 0))

        counts = {}
        for finding in results.findings:
            sev = finding.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        for sev, lbl in self.sev_labels.items():
            lbl.config(text=f"{sev.upper():<10} {counts.get(sev, 0)}")

        self._render_report(results)
        self.tbl_findings.set_rows(
            [[f.get("severity", ""), f.get("host", ""), f.get("name", ""),
              f.get("detail", ""), f.get("source", "")] for f in results.findings],
            tags=[f.get("severity", "info") for f in results.findings])

        self.tbl_secrets.set_rows(
            [[s.get("severity", ""), s.get("type", ""), s.get("value", ""), s.get("source", "")]
             for s in results.secrets],
            tags=[s.get("severity", "info") for s in results.secrets])

        self.tbl_hosts.set_rows(
            [[h.get("host", ""), h.get("status", ""), h.get("title", ""),
              ", ".join(h.get("tech", [])), ", ".join(str(p) for p in h.get("ports", [])),
              ", ".join(h.get("ips", [])), h.get("url", "")] for h in results.hosts])

        self.tbl_content.set_rows(
            [[c.get("url", ""), c.get("status", ""), c.get("length", ""), c.get("type", "")]
             for c in results.content])

        self.lst_subdomains.set_items(results.subdomains)
        self.lst_urls.set_items(results.urls)
        self.lst_js.set_items(results.js_files)
        self.lst_endpoints.set_items(results.js_endpoints)
        self.lst_params.set_items(results.params.get("names", []))

        if error:
            self.stage_text.set("Scan failed — see the Log tab")
            self.status_var.set(f"Error: {error}")
            messagebox.showerror("Scan failed", str(error))
        elif self.scanner and self.scanner.stop_event.is_set():
            self.stage_text.set("Scan stopped — partial results shown")
            self.status_var.set("Stopped by user")
        else:
            self.stage_text.set("Scan complete")
            self.status_var.set(
                f"Done — {stats['Findings']} findings "
                f"({stats['Critical/High']} critical/high), {stats['Live hosts']} live hosts")
            # Land on the triaged report, not the raw list — index 0 since the
            # Report tab was added ahead of the dashboard.
            if results.findings or results.hosts:
                self.tabs.select(0)

    # --- export -----------------------------------------------------------
    def _export(self):
        if not self.results:
            return
        outdir = self.outdir_var.get().strip() or os.path.join(os.getcwd(), "smarthunt-results")
        target_dir = os.path.join(outdir, self.results.target.replace(".", "_"))
        try:
            written = report.export_all(self.results, target_dir)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self._last_report = next((p for p in written if p.endswith(".html")), None)
        self.open_btn.config(state="normal" if self._last_report else "disabled")
        self.status_var.set(f"Exported {len(written)} files to {target_dir}")
        messagebox.showinfo("Export complete",
                            f"Wrote {len(written)} files to:\n{target_dir}\n\n"
                            "Includes JSON, HTML report, Markdown, findings CSV, "
                            "and plain-text lists for piping into other tools.")

    def _open_report(self):
        path = getattr(self, "_last_report", None)
        if path and os.path.isfile(path):
            webbrowser.open(f"file://{os.path.abspath(path)}")

    def _on_close(self):
        if self.scanner and self.scanner.running:
            if not messagebox.askyesno("Quit", "A scan is running. Stop it and quit?"):
                return
            self.scanner.stop()
        self.destroy()


def main():
    app = SmartHuntApp()
    app.mainloop()
