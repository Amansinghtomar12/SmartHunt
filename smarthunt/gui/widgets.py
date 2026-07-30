"""Reusable Tkinter widgets for the SmartHunt GUI."""

from __future__ import annotations

import tkinter as tk
import webbrowser
from tkinter import ttk

from . import theme


def dark_check(master, text, variable, command=None, **kw):
    """A checkbutton whose on/off state is unambiguous on a dark background.

    ``ttk`` indicators inherit the platform theme and render almost identically
    whether checked, unchecked or disabled — so the classic Tk widget is used
    here with explicit colours instead.
    """
    return tk.Checkbutton(
        master, text=text, variable=variable, command=command,
        bg=theme.BG, fg=theme.FG, selectcolor=theme.ACCENT,
        activebackground=theme.BG, activeforeground=theme.ACCENT,
        disabledforeground="#475569", font=theme.FONT,
        highlightthickness=0, bd=0, anchor="w", padx=2, **kw)


def dark_radio(master, text, variable, value, command=None, **kw):
    """A radiobutton with the same explicit dark-theme colouring."""
    return tk.Radiobutton(
        master, text=text, variable=variable, value=value, command=command,
        bg=theme.BG, fg=theme.FG, selectcolor=theme.ACCENT,
        activebackground=theme.BG, activeforeground=theme.ACCENT,
        disabledforeground="#475569", font=theme.FONT,
        highlightthickness=0, bd=0, anchor="w", padx=2, **kw)


class ModeSelector(tk.Frame):
    """A two-option card selector — which mode is active is unmistakable.

    Standard radio indicators render nearly identically selected vs unselected
    on a dark theme, and the mode is the single most important choice in the
    app, so each option is drawn as a full card that highlights when active.
    """

    SELECTED_BG = "#0c4a6e"

    def __init__(self, master, variable, options, command=None, **kw):
        super().__init__(master, bg=theme.BG, **kw)
        self.variable = variable
        self.command = command
        self._cards: dict[str, dict] = {}

        for value, title, subtitle in options:
            card = tk.Frame(self, bg=theme.PANEL, highlightthickness=1,
                            highlightbackground=theme.LINE, cursor="hand2")
            card.pack(fill="x", pady=(0, 6))
            inner = tk.Frame(card, bg=theme.PANEL)
            inner.pack(fill="x", padx=9, pady=7)
            glyph = tk.Label(inner, text="○", bg=theme.PANEL, fg=theme.MUTED,
                             font=("Segoe UI", 12))
            glyph.pack(side="left", padx=(0, 8))
            texts = tk.Frame(inner, bg=theme.PANEL)
            texts.pack(side="left", fill="x", expand=True)
            title_lbl = tk.Label(texts, text=title, bg=theme.PANEL, fg=theme.FG,
                                 font=("Segoe UI", 10, "bold"), anchor="w")
            title_lbl.pack(fill="x")
            sub_lbl = tk.Label(texts, text=subtitle, bg=theme.PANEL, fg=theme.MUTED,
                               font=("Segoe UI", 8), anchor="w", justify="left",
                               wraplength=250)
            sub_lbl.pack(fill="x")

            widgets = [card, inner, glyph, texts, title_lbl, sub_lbl]
            for widget in widgets:
                widget.bind("<Button-1>", lambda e, v=value: self.select(v))
            self._cards[value] = {"card": card, "glyph": glyph, "title": title_lbl,
                                  "sub": sub_lbl, "frames": [inner, texts]}

        variable.trace_add("write", lambda *_: self._render())
        self._render()

    def select(self, value):
        if self.variable.get() != value:
            self.variable.set(value)
        if self.command:
            self.command()

    def _render(self):
        active = self.variable.get()
        for value, parts in self._cards.items():
            on = value == active
            bg = self.SELECTED_BG if on else theme.PANEL
            parts["card"].configure(highlightbackground=theme.ACCENT if on else theme.LINE,
                                    highlightthickness=2 if on else 1, bg=bg)
            parts["glyph"].configure(text="◉" if on else "○", bg=bg,
                                     fg=theme.ACCENT if on else theme.MUTED)
            parts["title"].configure(bg=bg, fg="#ffffff" if on else theme.MUTED)
            parts["sub"].configure(bg=bg, fg="#bae6fd" if on else "#64748b")
            for frame in parts["frames"]:
                frame.configure(bg=bg)


class ResultTable(ttk.Frame):
    """A filterable, sortable, copyable table backed by a ``ttk.Treeview``.

    Rows are stored so filtering never loses data.  Double-clicking a row opens
    the first URL-looking cell in a browser; Ctrl+C copies the selection.
    """

    def __init__(self, master, columns, widths=None, filter_label="Filter", **kw):
        super().__init__(master, **kw)
        self.columns = list(columns)
        self._rows: list[tuple] = []
        self._sort_col: int | None = None
        self._sort_desc = False

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=6, pady=(6, 3))
        ttk.Label(bar, text=f"{filter_label}:", style="Muted.TLabel").pack(side="left")
        self.filter_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self.filter_var, width=34)
        entry.pack(side="left", padx=(6, 10))
        self.filter_var.trace_add("write", lambda *_: self._refresh())
        self.count_label = ttk.Label(bar, text="0 rows", style="Muted.TLabel")
        self.count_label.pack(side="left")
        ttk.Button(bar, text="Copy all", width=9,
                   command=self.copy_all).pack(side="right", padx=2)
        ttk.Button(bar, text="Clear filter", width=11,
                   command=lambda: self.filter_var.set("")).pack(side="right", padx=2)

        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.tree = ttk.Treeview(wrap, columns=self.columns, show="headings", selectmode="extended")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        widths = widths or [160] * len(self.columns)
        for idx, col in enumerate(self.columns):
            self.tree.heading(col, text=col, anchor="w",
                              command=lambda i=idx: self._sort_by(i))
            self.tree.column(col, width=widths[idx] if idx < len(widths) else 160,
                             anchor="w", stretch=True)

        for name, color in theme.SEVERITY.items():
            self.tree.tag_configure(name, foreground=color)
        self.tree.tag_configure("odd", background=theme.PANEL_ALT)

        self.tree.bind("<Double-1>", self._open_selected)
        self.tree.bind("<Control-c>", lambda e: self.copy_selection())
        self._menu = tk.Menu(self, tearoff=0, bg=theme.PANEL, fg=theme.FG,
                             activebackground=theme.ACCENT, activeforeground="#000")
        self._menu.add_command(label="Copy row", command=self.copy_selection)
        self._menu.add_command(label="Copy column value", command=self._copy_cell)
        self._menu.add_command(label="Open in browser", command=lambda: self._open_selected(None))
        self._menu.add_separator()
        self._menu.add_command(label="Copy all rows", command=self.copy_all)
        self.tree.bind("<Button-3>", self._popup)

    # --- data ------------------------------------------------------------
    def set_rows(self, rows, tags=None):
        """Replace all rows. ``tags`` is an optional per-row tag list."""
        self._rows = [(tuple(str(c) for c in row), (tags[i] if tags else None))
                      for i, row in enumerate(rows)]
        self._refresh()

    def add_row(self, row, tag=None):
        self._rows.append((tuple(str(c) for c in row), tag))
        self._refresh()

    def clear(self):
        self._rows = []
        self._refresh()

    def _visible_rows(self):
        needle = self.filter_var.get().strip().lower()
        if not needle:
            return self._rows
        return [r for r in self._rows if needle in " ".join(r[0]).lower()]

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        rows = self._visible_rows()
        if self._sort_col is not None:
            idx = self._sort_col

            def key(item):
                value = item[0][idx] if idx < len(item[0]) else ""
                try:
                    return (0, float(value))
                except (TypeError, ValueError):
                    return (1, value.lower())

            rows = sorted(rows, key=key, reverse=self._sort_desc)
        for i, (values, tag) in enumerate(rows):
            tags = [t for t in (tag, "odd" if i % 2 else None) if t]
            self.tree.insert("", "end", values=values, tags=tags)
        total = len(self._rows)
        shown = len(rows)
        self.count_label.config(
            text=f"{shown} rows" if shown == total else f"{shown} of {total} rows")

    def _sort_by(self, idx):
        self._sort_desc = not self._sort_desc if self._sort_col == idx else False
        self._sort_col = idx
        self._refresh()

    # --- interaction ------------------------------------------------------
    def _popup(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            if row not in self.tree.selection():
                self.tree.selection_set(row)
            self._last_col = self.tree.identify_column(event.x)
            self._menu.tk_popup(event.x_root, event.y_root)

    def _selected_values(self):
        return [self.tree.item(i, "values") for i in self.tree.selection()]

    def copy_selection(self):
        rows = self._selected_values()
        if rows:
            self._to_clipboard("\n".join("\t".join(str(c) for c in r) for r in rows))

    def _copy_cell(self):
        rows = self._selected_values()
        col = getattr(self, "_last_col", "#1")
        try:
            idx = int(col.lstrip("#")) - 1
        except ValueError:
            idx = 0
        values = [r[idx] for r in rows if idx < len(r)]
        if values:
            self._to_clipboard("\n".join(str(v) for v in values))

    def copy_all(self):
        rows = [r[0] for r in self._visible_rows()]
        if rows:
            self._to_clipboard("\n".join("\t".join(r) for r in rows))

    def _to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _open_selected(self, _event):
        for row in self._selected_values():
            for cell in row:
                cell = str(cell)
                if cell.startswith("http"):
                    webbrowser.open(cell)
                    return


class ListPane(ttk.Frame):
    """A filterable plain-text list (subdomains, URLs, endpoints, ...)."""

    def __init__(self, master, label="Filter", **kw):
        super().__init__(master, **kw)
        self._items: list[str] = []

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=6, pady=(6, 3))
        ttk.Label(bar, text=f"{label}:", style="Muted.TLabel").pack(side="left")
        self.filter_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.filter_var, width=34).pack(side="left", padx=(6, 10))
        self.filter_var.trace_add("write", lambda *_: self._refresh())
        self.count_label = ttk.Label(bar, text="0 items", style="Muted.TLabel")
        self.count_label.pack(side="left")
        ttk.Button(bar, text="Copy all", width=9, command=self.copy_all).pack(side="right", padx=2)
        ttk.Button(bar, text="Clear filter", width=11,
                   command=lambda: self.filter_var.set("")).pack(side="right", padx=2)

        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.text = tk.Text(wrap, bg=theme.PANEL, fg=theme.FG, font=theme.FONT_MONO,
                            insertbackground=theme.FG, relief="flat", wrap="none",
                            selectbackground="#0369a1", padx=8, pady=6)
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.text.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set, state="disabled")
        self.text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

    def set_items(self, items):
        self._items = [str(i) for i in items]
        self._refresh()

    def _refresh(self):
        needle = self.filter_var.get().strip().lower()
        shown = [i for i in self._items if needle in i.lower()] if needle else self._items
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", "\n".join(shown))
        self.text.configure(state="disabled")
        total = len(self._items)
        self.count_label.config(
            text=f"{len(shown)} items" if len(shown) == total else f"{len(shown)} of {total} items")

    def copy_all(self):
        needle = self.filter_var.get().strip().lower()
        shown = [i for i in self._items if needle in i.lower()] if needle else self._items
        if shown:
            self.clipboard_clear()
            self.clipboard_append("\n".join(shown))


class LogPane(ttk.Frame):
    """Colour-coded, auto-scrolling log console."""

    LEVEL_COLORS = {
        "info": theme.FG,
        "stage": theme.ACCENT,
        "found": theme.FOUND,
        "warn": theme.WARN,
        "error": theme.ERR,
        "ok": theme.OK,
    }

    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=6, pady=(6, 3))
        self.autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Auto-scroll", variable=self.autoscroll).pack(side="left")
        ttk.Button(bar, text="Clear", width=8, command=self.clear).pack(side="right", padx=2)
        ttk.Button(bar, text="Copy", width=8, command=self.copy_all).pack(side="right", padx=2)

        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.text = tk.Text(wrap, bg="#0b1220", fg=theme.FG, font=theme.FONT_MONO,
                            relief="flat", wrap="word", padx=8, pady=6,
                            insertbackground=theme.FG, selectbackground="#0369a1")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=vsb.set, state="disabled")
        self.text.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        for level, color in self.LEVEL_COLORS.items():
            self.text.tag_configure(level, foreground=color)
        self.text.tag_configure("stage", foreground=theme.ACCENT,
                                font=("Consolas", 9, "bold"))
        self.text.tag_configure("ts", foreground=theme.MUTED)

    def append(self, level, message, timestamp=""):
        self.text.configure(state="normal")
        if timestamp:
            self.text.insert("end", f"{timestamp} ", "ts")
        self.text.insert("end", f"{message}\n", level if level in self.LEVEL_COLORS else "info")
        self.text.configure(state="disabled")
        if self.autoscroll.get():
            self.text.see("end")

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")

    def copy_all(self):
        self.clipboard_clear()
        self.clipboard_append(self.text.get("1.0", "end-1c"))


class StatCard(ttk.Frame):
    """A single big-number summary tile."""

    def __init__(self, master, label, value="0", **kw):
        super().__init__(master, style="Panel.TFrame", padding=(14, 10), **kw)
        self.value_var = tk.StringVar(value=str(value))
        ttk.Label(self, textvariable=self.value_var, style="Stat.TLabel").pack(anchor="w")
        ttk.Label(self, text=label.upper(), style="StatLbl.TLabel").pack(anchor="w")

    def set(self, value):
        self.value_var.set(str(value))
