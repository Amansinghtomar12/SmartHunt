"""Tkinter front-end for SmartHunt."""

from __future__ import annotations


def main():
    """Launch the GUI, with a friendly message if Tkinter is unavailable."""
    try:
        import tkinter  # noqa: F401
    except ImportError:
        raise SystemExit(
            "Tkinter is not installed.\n\n"
            "  Debian/Ubuntu : sudo apt install python3-tk\n"
            "  Fedora/RHEL   : sudo dnf install python3-tkinter\n"
            "  Arch          : sudo pacman -S tk\n"
            "  macOS (brew)  : brew install python-tk\n"
            "  Windows       : reinstall Python with the 'tcl/tk' option checked\n\n"
            "Or run headless:  python smarthunt.py --cli example.com"
        )
    from .app import main as _main
    _main()


__all__ = ["main"]
