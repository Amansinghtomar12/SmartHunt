"""Dark theme palette and ttk style setup for the SmartHunt GUI."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

# Palette
BG = "#0f172a"          # window background
PANEL = "#1e293b"       # panels / entries
PANEL_ALT = "#172033"   # alternating rows
LINE = "#334155"        # borders
FG = "#e2e8f0"          # primary text
MUTED = "#94a3b8"       # secondary text
ACCENT = "#38bdf8"      # highlight / focus
OK = "#22c55e"
WARN = "#f59e0b"
ERR = "#ef4444"
FOUND = "#a78bfa"

SEVERITY = {
    "critical": "#dc2626",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#94a3b8",
    "unknown": "#94a3b8",
}

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 16, "bold")
FONT_MONO = ("Consolas", 9)


def apply(root: tk.Tk) -> ttk.Style:
    """Apply the SmartHunt dark theme to ``root`` and return the style object."""
    root.configure(bg=BG)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:  # pragma: no cover
        pass

    style.configure(".", background=BG, foreground=FG, font=FONT,
                    fieldbackground=PANEL, bordercolor=LINE, focuscolor=ACCENT)
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL, relief="flat")
    style.configure("TLabel", background=BG, foreground=FG, font=FONT)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
    style.configure("Title.TLabel", background=BG, foreground=ACCENT, font=FONT_TITLE)
    style.configure("Head.TLabel", background=BG, foreground=FG, font=FONT_BOLD)
    style.configure("Stat.TLabel", background=PANEL, foreground=ACCENT,
                    font=("Segoe UI", 20, "bold"))
    style.configure("StatLbl.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 8))

    style.configure("TLabelframe", background=BG, foreground=ACCENT,
                    bordercolor=LINE, relief="solid", borderwidth=1)
    style.configure("TLabelframe.Label", background=BG, foreground=ACCENT, font=FONT_BOLD)

    style.configure("TEntry", fieldbackground=PANEL, foreground=FG,
                    insertcolor=FG, bordercolor=LINE, padding=5)
    style.map("TEntry", bordercolor=[("focus", ACCENT)])

    style.configure("TCombobox", fieldbackground=PANEL, background=PANEL,
                    foreground=FG, arrowcolor=ACCENT, bordercolor=LINE, padding=4)
    style.map("TCombobox", fieldbackground=[("readonly", PANEL)],
              foreground=[("readonly", FG)])

    style.configure("TButton", background=PANEL, foreground=FG, borderwidth=1,
                    bordercolor=LINE, padding=(12, 6), font=FONT)
    style.map("TButton",
              background=[("active", LINE), ("disabled", "#1a2436")],
              foreground=[("disabled", "#4b5563")])

    style.configure("Start.TButton", background="#15803d", foreground="#ffffff",
                    font=("Segoe UI", 11, "bold"), padding=(20, 9))
    style.map("Start.TButton", background=[("active", "#16a34a"), ("disabled", "#1a2436")],
              foreground=[("disabled", "#4b5563")])

    style.configure("Stop.TButton", background="#b91c1c", foreground="#ffffff",
                    font=("Segoe UI", 11, "bold"), padding=(20, 9))
    style.map("Stop.TButton", background=[("active", "#dc2626"), ("disabled", "#1a2436")],
              foreground=[("disabled", "#4b5563")])

    style.configure("Accent.TButton", background="#0369a1", foreground="#ffffff", padding=(14, 7))
    style.map("Accent.TButton", background=[("active", "#0284c7"), ("disabled", "#1a2436")],
              foreground=[("disabled", "#4b5563")])

    style.configure("TCheckbutton", background=BG, foreground=FG, font=FONT,
                    indicatorcolor=PANEL, focuscolor=BG)
    style.map("TCheckbutton", background=[("active", BG)],
              indicatorcolor=[("selected", ACCENT), ("pressed", ACCENT)])

    style.configure("TRadiobutton", background=BG, foreground=FG, font=FONT, focuscolor=BG)
    style.map("TRadiobutton", background=[("active", BG)],
              indicatorcolor=[("selected", ACCENT)])

    style.configure("TNotebook", background=BG, bordercolor=LINE, tabmargins=(2, 4, 2, 0))
    style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                    padding=(10, 7), font=FONT, bordercolor=LINE)
    style.map("TNotebook.Tab",
              background=[("selected", BG)],
              foreground=[("selected", ACCENT)],
              expand=[("selected", (1, 1, 1, 0))])

    style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=FG, bordercolor=LINE, rowheight=23, font=("Segoe UI", 9))
    style.configure("Treeview.Heading", background=BG, foreground=ACCENT,
                    font=FONT_BOLD, relief="flat", padding=5)
    style.map("Treeview.Heading", background=[("active", LINE)])
    style.map("Treeview", background=[("selected", "#0369a1")],
              foreground=[("selected", "#ffffff")])

    style.configure("TProgressbar", background=ACCENT, troughcolor=PANEL,
                    bordercolor=LINE, lightcolor=ACCENT, darkcolor=ACCENT, thickness=16)

    style.configure("TScale", background=BG, troughcolor=PANEL)
    style.configure("Vertical.TScrollbar", background=PANEL, troughcolor=BG,
                    bordercolor=LINE, arrowcolor=MUTED)
    style.configure("Horizontal.TScrollbar", background=PANEL, troughcolor=BG,
                    bordercolor=LINE, arrowcolor=MUTED)
    style.configure("TSeparator", background=LINE)

    return style
