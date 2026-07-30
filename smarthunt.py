#!/usr/bin/env python3
"""SmartHunt — GUI bug-hunting recon suite.

    python smarthunt.py                      # launch the desktop GUI
    python smarthunt.py example.com          # GUI, target pre-filled
    python smarthunt.py --web                # browser UI on http://127.0.0.1:8777
    python smarthunt.py --web --port 9000 --open
    python smarthunt.py --cli example.com    # headless, same engine
    python smarthunt.py --cli '*.example.com' --out results/
    python smarthunt.py --tools               # list detected external tools
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from smarthunt import __version__, report  # noqa: E402
from smarthunt.engine import (DEFAULT_ENABLED, STAGES, ScanConfig, Scanner,  # noqa: E402
                              normalize_target)
from smarthunt.tools import REGISTRY, detect_tools  # noqa: E402

# ANSI colours for CLI output (disabled when not a TTY)
_TTY = sys.stdout.isatty()
C = {
    "reset": "\033[0m" if _TTY else "", "dim": "\033[2m" if _TTY else "",
    "bold": "\033[1m" if _TTY else "", "cyan": "\033[36m" if _TTY else "",
    "green": "\033[32m" if _TTY else "", "yellow": "\033[33m" if _TTY else "",
    "red": "\033[31m" if _TTY else "", "magenta": "\033[35m" if _TTY else "",
}
_LEVEL_COLOR = {"stage": C["cyan"] + C["bold"], "found": C["magenta"],
                "warn": C["yellow"], "error": C["red"], "info": ""}


def list_tools():
    inv = detect_tools()
    print(f"\n{C['bold']}SmartHunt v{__version__} — external tool inventory{C['reset']}\n")
    current = None
    for tool in REGISTRY:
        if tool.category != current:
            current = tool.category
            print(f"\n{C['cyan']}{current}{C['reset']}")
        if inv.has(tool.name):
            print(f"  {C['green']}●{C['reset']} {tool.name:<20} {C['dim']}{tool.description}{C['reset']}")
        else:
            print(f"  {C['dim']}○ {tool.name:<20} {tool.description}")
            print(f"    {' ' * 20} install: {tool.install}{C['reset']}")
    print(f"\n{inv.summary()}\n")


def run_cli(args):
    try:
        mode, apex = normalize_target(args.target)
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    if args.wildcard:
        mode = "wildcard"

    stages = set(DEFAULT_ENABLED[mode])
    if args.stages:
        requested = {s.strip() for s in args.stages.split(",") if s.strip()}
        valid = {k for k, _, modes in STAGES if mode in modes}
        unknown = requested - valid
        if unknown:
            sys.exit(f"error: unknown stage(s) for {mode} mode: {', '.join(sorted(unknown))}\n"
                     f"valid: {', '.join(sorted(valid))}")
        stages = requested
    if args.all:
        stages = {k for k, _, modes in STAGES if mode in modes}

    scope = f"*.{apex}" if mode == "wildcard" else apex
    if not args.yes:
        print(f"\nTarget scope : {scope}\nMode         : {mode}\n"
              f"Modules      : {', '.join(sorted(stages))}\n")
        print("This sends live traffic to the target. Only continue if you own it or\n"
              "have written authorization to test it (e.g. an in-scope bounty program).")
        if input("\nConfirm you are authorized [y/N]: ").strip().lower() not in ("y", "yes"):
            sys.exit("aborted")

    config = ScanConfig(
        target=apex, mode=mode, enabled_stages=stages, threads=args.threads,
        crawl_depth=args.depth, max_pages=args.max_pages, max_js_files=args.max_js,
        bruteforce_subdomains=not args.no_brute,
        subdomain_wordlist=args.sub_wordlist or "", content_wordlist=args.content_wordlist or "",
        ports=[int(p) for p in args.ports.split(",") if p.strip().isdigit()] if args.ports else [],
        output_dir=args.out, authorized=True,
    )

    def log(level, message):
        color = _LEVEL_COLOR.get(level, "")
        print(f"{color}{message}{C['reset']}", flush=True)

    finished = {"done": False}

    def on_done(results, error):
        finished["done"] = True

    scanner = Scanner(config, on_log=log, on_done=on_done)
    scanner.start()
    try:
        while scanner.running:
            scanner._thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\ninterrupted — stopping…")
        scanner.stop()
        scanner._thread.join(timeout=30)

    results = scanner.results
    print(f"\n{C['bold']}Summary{C['reset']}")
    for key, value in results.stats().items():
        print(f"  {key:<16} {value}")

    if results.findings:
        print(f"\n{C['bold']}Findings{C['reset']}")
        for f in results.findings[:40]:
            sev = f["severity"]
            color = {"critical": C["red"] + C["bold"], "high": C["red"],
                     "medium": C["yellow"], "low": C["cyan"]}.get(sev, C["dim"])
            print(f"  {color}[{sev:>8}]{C['reset']} {f['host']:<32} {f['name']} "
                  f"{C['dim']}{str(f['detail'])[:70]}{C['reset']}")
        if len(results.findings) > 40:
            print(f"  {C['dim']}… and {len(results.findings) - 40} more (see the report){C['reset']}")

    outdir = os.path.join(args.out, apex.replace(".", "_"))
    written = report.export_all(results, outdir)
    print(f"\n{C['green']}Wrote {len(written)} files to {outdir}{C['reset']}")
    for path in written:
        print(f"  {C['dim']}{path}{C['reset']}")


def main():
    parser = argparse.ArgumentParser(
        prog="smarthunt", description="SmartHunt — GUI bug-hunting recon suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n", 2)[2])
    parser.add_argument("target", nargs="?", help="example.com or '*.example.com'")
    parser.add_argument("--cli", action="store_true", help="run headless instead of the GUI")
    parser.add_argument("--web", action="store_true",
                        help="serve the browser UI instead of the desktop GUI")
    parser.add_argument("--port", type=int, default=8777, help="port for --web (default 8777)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address for --web (default 127.0.0.1, loopback only)")
    parser.add_argument("--open", action="store_true",
                        help="open the browser automatically with --web")
    parser.add_argument("--wildcard", "-w", action="store_true", help="force wildcard mode")
    parser.add_argument("--tools", action="store_true", help="list external tool inventory and exit")
    parser.add_argument("--stages", help="comma-separated module keys to run")
    parser.add_argument("--all", action="store_true", help="run every module for the mode")
    parser.add_argument("--threads", type=int, default=40)
    parser.add_argument("--depth", type=int, default=2, help="crawl depth")
    parser.add_argument("--max-pages", type=int, default=300)
    parser.add_argument("--max-js", type=int, default=400)
    parser.add_argument("--ports", help="comma-separated ports, e.g. 80,443,8080")
    parser.add_argument("--no-brute", action="store_true", help="skip DNS bruteforce")
    parser.add_argument("--sub-wordlist", help="subdomain wordlist file")
    parser.add_argument("--content-wordlist", help="content-discovery wordlist file")
    parser.add_argument("--out", default="smarthunt-results", help="output directory")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="skip the authorization prompt (you still assert authorization)")
    parser.add_argument("--version", action="version", version=f"SmartHunt {__version__}")
    args = parser.parse_args()

    if args.tools:
        list_tools()
        return
    if args.web:
        from smarthunt.webapp import serve
        serve(host=args.host, port=args.port, open_browser=args.open)
        return
    if args.cli:
        if not args.target:
            parser.error("--cli requires a target")
        run_cli(args)
        return

    from smarthunt.gui import main as gui_main
    if args.target:
        os.environ["SMARTHUNT_TARGET"] = args.target
    gui_main()


if __name__ == "__main__":
    main()
