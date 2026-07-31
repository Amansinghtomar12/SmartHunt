#!/usr/bin/env python3
"""SmartHunt — GUI bug-hunting recon suite.

    python smarthunt.py                      # launch the desktop GUI
    python smarthunt.py example.com          # GUI, target pre-filled
    python smarthunt.py --web                # browser UI on http://127.0.0.1:8777
    python smarthunt.py --web --port 9000 --open
    python smarthunt.py --cli example.com    # headless, same engine
    python smarthunt.py --cli '*.example.com' --out results/
    python smarthunt.py --cli example.com --ai   # AI retunes the scan and
                                                 # writes the report
    python smarthunt.py --tools               # list detected tools and AI status
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
    print(f"\n{inv.summary()}")

    from smarthunt import ai
    status = ai.detect()
    mark = f"{C['green']}●{C['reset']}" if status["available"] else f"{C['dim']}○{C['reset']}"
    print(f"\n{C['cyan']}AI assist{C['reset']}")
    print(f"  {mark} {status['detail']}")
    print(f"  {C['dim']}enable with --ai (off by default){C['reset']}\n")


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
        collaborator=args.collaborator, use_sqlmap=not args.no_sqlmap,
        cve_online=args.cve_online,
        exhaustive=args.exhaustive, max_rounds=args.rounds,
        auth_headers=_maybe_file(args.auth_headers),
        auth_cookies=args.auth_cookie, auth_bearer=args.auth_bearer,
        auth_check_url=args.auth_check_url, auth_check_marker=args.auth_check_text,
        victim_headers=_maybe_file(args.victim_headers),
        victim_cookies=args.victim_cookie, victim_bearer=args.victim_bearer,
        ai_enabled=args.ai, ai_model=args.ai_model,
        ai_advice=not args.no_ai_tuning, ai_report=not args.no_ai_report,
        ai_budget=args.ai_budget,
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

    # The headline is one triaged, reportable finding — not a finding dump.
    # The full list still ships in the exported JSON/CSV for your own digging.
    triaged = results.report or {}
    kind = triaged.get("kind")
    if kind == "report":
        sev = triaged.get("severity", "")
        color = {"critical": C["red"] + C["bold"], "high": C["red"],
                 "medium": C["yellow"], "low": C["cyan"]}.get(sev, C["dim"])
        written_by = (" (AI-written from the captured evidence)"
                      if triaged.get("ai_written") else "")
        print(f"\n{C['bold']}Reportable finding{C['reset']}  "
              f"{color}[{sev}]{C['reset']}{C['dim']}{written_by}{C['reset']}")
        print(f"{C['dim']}{'─' * 68}{C['reset']}")
        print(triaged.get("markdown", ""))
    elif kind == "evidence_needed":
        print(f"\n{C['bold']}{C['yellow']}Not yet reportable{C['reset']}")
        print(f"{C['dim']}{'─' * 68}{C['reset']}")
        print(triaged.get("markdown", ""))
    else:
        print(f"\n{C['dim']}No reportable vulnerability found with the current "
              f"evidence.{C['reset']}")

    if results.findings:
        crit = sum(1 for f in results.findings if f["severity"] in ("critical", "high"))
        print(f"\n{C['dim']}({len(results.findings)} raw findings in total, {crit} "
              f"critical/high — full list in the exported JSON and CSV.){C['reset']}")

    outdir = os.path.join(args.out, apex.replace(".", "_"))
    written = report.export_all(results, outdir)
    print(f"\n{C['green']}Wrote {len(written)} files to {outdir}{C['reset']}")
    for path in written:
        print(f"  {C['dim']}{path}{C['reset']}")


def _maybe_file(value: str) -> str:
    """Accept either a path to a header block or the block pasted inline."""
    if value and os.path.isfile(value):
        with open(value, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    return value


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
    auth_group = parser.add_argument_group(
        "authenticated testing",
        "Supply a session you already have. Two sessions (yours and a second "
        "account you also control) enable access-control/IDOR proof.")
    auth_group.add_argument("--auth-headers", default="",
                            help="file containing a raw header block for Account A "
                                 "(paste from Burp or devtools), or the block itself")
    auth_group.add_argument("--auth-cookie", default="",
                            help="Cookie header value for Account A")
    auth_group.add_argument("--auth-bearer", default="",
                            help="bearer token for Account A")
    auth_group.add_argument("--auth-check-url", default="",
                            help="a URL that requires login, used to verify the session")
    auth_group.add_argument("--auth-check-text", default="",
                            help="text present only when logged in (e.g. your username)")
    auth_group.add_argument("--victim-headers", default="",
                            help="raw header block (or file) for Account B")
    auth_group.add_argument("--victim-cookie", default="",
                            help="Cookie header value for Account B")
    auth_group.add_argument("--victim-bearer", default="",
                            help="bearer token for Account B")

    ai_group = parser.add_argument_group(
        "AI assist (optional)",
        "Off unless --ai is passed. Uses the Claude Code CLI on your Claude "
        "subscription when it is installed, otherwise the anthropic SDK with "
        "your own API credentials. It retunes the scan and writes the final "
        "report; it can never decide that something is a bug — every claim it "
        "writes is checked against the captured evidence and dropped if it is "
        "not backed by it. Scan metadata (host names, counts, the redacted "
        "evidence for the one finding) leaves your machine when this is on.")
    ai_group.add_argument("--ai", action="store_true",
                          help="enable the AI assist")
    ai_group.add_argument("--ai-model", default="",
                          help="model to use (default: the module default)")
    ai_group.add_argument("--ai-budget", type=int, default=8,
                          help="max model calls per scan (default 8)")
    ai_group.add_argument("--no-ai-tuning", action="store_true",
                          help="with --ai: write the report but do not retune the scan")
    ai_group.add_argument("--no-ai-report", action="store_true",
                          help="with --ai: retune the scan but keep the template report")

    parser.add_argument("--exhaustive", "-E", action="store_true",
                        help="leave nothing behind: raise every cap and loop "
                             "discovery until a round finds nothing new")
    parser.add_argument("--rounds", type=int, default=4,
                        help="max discovery rounds for --exhaustive (default 4)")
    parser.add_argument("--cve-online", action="store_true",
                        help="also query OSV/NVD for CVEs (slower, rate-limited)")
    parser.add_argument("--collaborator", default="",
                        help="host that observes SSRF callbacks, e.g. your "
                             "Burp Collaborator or interactsh domain")
    parser.add_argument("--no-sqlmap", action="store_true",
                        help="skip sqlmap confirmation on proven injection points")
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
