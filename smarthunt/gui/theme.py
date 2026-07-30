"""Dark theme palette and ttk style setup for the SmartHunt GUI."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

# Palette
BG = "#050807"          # window background
PANEL = "#0a1410"       # panels / entries
PANEL_ALT = "#071009"   # alternating rows
LINE = "#16341f"        # borders
FG = "#c8f7d4"          # primary text
MUTED = "#5f9d74"       # secondary text
ACCENT = "#00ff9c"      # highlight / focus
OK = "#00ff9c"
WARN = "#ffb020"
ERR = "#ff3b5c"
FOUND = "#ff5cf0"
DIM = "#3a6b49"         # de-emphasised text
BG_DEEP = "#020403"     # log / text-widget background
ACCENT_DEEP = "#04241a" # selected-row and selected-card fill

SEVERITY = {
    "critical": "#ff2d55",
    "high": "#ff7a1a",
    "medium": "#ffd21e",
    "low": "#22d3ee",
    "info": "#5f9d74",
    "unknown": "#5f9d74",
}

#: Terminal look: everything monospace, same as the browser skin.
#: The family is resolved in :func:`apply`, not here — ``font.families()``
#: needs a live Tk root, so probing at import time always falls through to the
#: last candidate regardless of what is installed.
_MONO_CANDIDATES = ("JetBrains Mono", "Fira Code", "DejaVu Sans Mono",
                    "Liberation Mono", "Consolas", "Menlo", "Courier New")
_MONO_FAMILY = "Courier New"

FONT = (_MONO_FAMILY, 10)
FONT_BOLD = (_MONO_FAMILY, 10, "bold")
FONT_TITLE = (_MONO_FAMILY, 16, "bold")
FONT_MONO = (_MONO_FAMILY, 9)
FONT_SMALL = (_MONO_FAMILY, 9)
FONT_BIG = (_MONO_FAMILY, 20, "bold")
FONT_BTN = (_MONO_FAMILY, 11, "bold")


def _resolve_mono():
    """Pick the best monospace family the system actually has."""
    global _MONO_FAMILY, FONT, FONT_BOLD, FONT_TITLE, FONT_MONO, FONT_SMALL
    global FONT_BIG, FONT_BTN
    try:
        import tkinter.font as tkfont
        available = set(tkfont.families())
    except Exception:
        return
    for candidate in _MONO_CANDIDATES:
        if candidate in available:
            _MONO_FAMILY = candidate
            break
    FONT = (_MONO_FAMILY, 10)
    FONT_BOLD = (_MONO_FAMILY, 10, "bold")
    FONT_TITLE = (_MONO_FAMILY, 16, "bold")
    FONT_MONO = (_MONO_FAMILY, 9)
    FONT_SMALL = (_MONO_FAMILY, 9)
    FONT_BIG = (_MONO_FAMILY, 20, "bold")
    FONT_BTN = (_MONO_FAMILY, 11, "bold")


def apply(root: tk.Tk) -> ttk.Style:
    """Apply the SmartHunt terminal theme to ``root`` and return the style object."""
    _resolve_mono()   # needs a live root, so it cannot happen at import time
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
    style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=FONT_SMALL)
    style.configure("Title.TLabel", background=BG, foreground=ACCENT, font=FONT_TITLE)
    style.configure("Head.TLabel", background=BG, foreground=FG, font=FONT_BOLD)
    style.configure("Stat.TLabel", background=PANEL, foreground=ACCENT,
                    font=FONT_BIG)
    style.configure("StatLbl.TLabel", background=PANEL, foreground=MUTED, font=(_MONO_FAMILY, 8))

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
              background=[("active", LINE), ("disabled", PANEL)],
              foreground=[("disabled", DIM)])

    style.configure("Start.TButton", background="#0b3d24", foreground=ACCENT,
                    font=FONT_BTN, padding=(20, 9))
    style.map("Start.TButton", background=[("active", "#0f5c34"), ("disabled", PANEL)],
              foreground=[("disabled", DIM)])

    style.configure("Stop.TButton", background="#4a0d18", foreground="#ff8fa3",
                    font=FONT_BTN, padding=(20, 9))
    style.map("Stop.TButton", background=[("active", "#6d1222"), ("disabled", PANEL)],
              foreground=[("disabled", DIM)])

    style.configure("Accent.TButton", background="#052b33", foreground="#22d3ee", padding=(14, 7))
    style.map("Accent.TButton", background=[("active", "#07404d"), ("disabled", PANEL)],
              foreground=[("disabled", DIM)])

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
                    foreground=FG, bordercolor=LINE, rowheight=23, font=FONT_SMALL)
    style.configure("Treeview.Heading", background=BG, foreground=ACCENT,
                    font=FONT_BOLD, relief="flat", padding=5)
    style.map("Treeview.Heading", background=[("active", LINE)])
    style.map("Treeview", background=[("selected", ACCENT_DEEP)],
              foreground=[("selected", ACCENT)])

    style.configure("TProgressbar", background=ACCENT, troughcolor=PANEL,
                    bordercolor=LINE, lightcolor=ACCENT, darkcolor=ACCENT, thickness=16)

    style.configure("TScale", background=BG, troughcolor=PANEL)
    style.configure("Vertical.TScrollbar", background=PANEL, troughcolor=BG,
                    bordercolor=LINE, arrowcolor=MUTED)
    style.configure("Horizontal.TScrollbar", background=PANEL, troughcolor=BG,
                    bordercolor=LINE, arrowcolor=MUTED)
    style.configure("TSeparator", background=LINE)

    return style
