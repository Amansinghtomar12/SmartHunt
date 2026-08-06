"""Declarative command table for the wider tool arsenal.

The core stages in :mod:`smarthunt.modules` drive a hand-written integration for
each tool they use, because those need bespoke parsing.  Everything else lives
here: a table of ``(tool, stage, argv, parser)`` rows plus one generic runner.

Adding a tool is a single row.  Every installed tool whose row matches the
current stage runs, and the outputs are merged — because the whole point of
keeping fifteen subdomain sources around is that they disagree with each other.

Nothing here is required.  A row whose binary is absent is skipped silently,
so a fresh clone still scans with zero setup.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import tempfile
import threading
from dataclasses import dataclass
from typing import Callable

from .tools import ToolInventory, run

# Stage keys the pipeline asks for.
S_SUBDOMAIN = "subdomains"
S_PERMUTE = "permute"
S_OSINT = "osint"
S_URLS = "urls"
S_JS = "js"
S_PARAMS = "params"
S_CONTENT = "content"
S_TAKEOVER = "takeover"
S_VULN = "vulns"
S_TLS = "tls"
S_CLOUD = "cloud"
S_CMS = "cms"
S_API = "api"

HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


@dataclass(frozen=True)
class Row:
    """One tool invocation: how to build it, and how to read what comes back."""

    tool: str
    stage: str
    argv: Callable[[dict], list]      # ctx -> argv, or [] to skip
    parse: str = "hosts"              # hosts | urls | lines | json_urls | vuln
    stdin: Callable[[dict], str] | None = None
    timeout: int = 300
    note: str = ""


def _domain(ctx):
    return ctx.get("domain", "")


def _hosts_text(ctx):
    return "\n".join(sorted(ctx.get("hosts", ())))


def _urls_text(ctx):
    return "\n".join(list(ctx.get("urls", ()))[:20000])


def _live_urls(ctx):
    return [h for h in ctx.get("live_urls", ()) if h]


#: The table.  Commands use each tool's documented non-interactive flags.
ROWS: tuple[Row, ...] = (
    # --- subdomain sources ---------------------------------------------------
    Row("sublist3r", S_SUBDOMAIN, lambda c: ["sublist3r", "-d", _domain(c), "-o", "/dev/stdout"]),
    Row("knockpy", S_SUBDOMAIN, lambda c: ["knockpy", "-d", _domain(c), "--no-http", "--silent"]),
    Row("crobat", S_SUBDOMAIN, lambda c: ["crobat", "-s", _domain(c)]),
    Row("haktrails", S_SUBDOMAIN, lambda c: ["haktrails", "subdomains"],
        stdin=lambda c: _domain(c)),
    Row("cero", S_SUBDOMAIN, lambda c: ["cero", _domain(c)]),
    Row("shosubgo", S_SUBDOMAIN, lambda c: ["shosubgo", "-d", _domain(c)]),

    # --- permutation ---------------------------------------------------------
    Row("alterx", S_PERMUTE, lambda c: ["alterx", "-silent"], stdin=_hosts_text),
    Row("ripgen", S_PERMUTE, lambda c: ["ripgen", "-d", "-"], stdin=_hosts_text),

    # --- OSINT / attack surface ---------------------------------------------
    Row("tlsx", S_OSINT, lambda c: ["tlsx", "-silent", "-san", "-resp-only"],
        stdin=_hosts_text),
    Row("cdncheck", S_OSINT, lambda c: ["cdncheck", "-silent", "-resp"],
        parse="lines", stdin=_hosts_text),
    Row("asnmap", S_OSINT, lambda c: ["asnmap", "-d", _domain(c), "-silent"], parse="lines"),
    Row("hakip2host", S_OSINT, lambda c: ["hakip2host"], parse="lines", stdin=_hosts_text),
    Row("uncover", S_OSINT, lambda c: ["uncover", "-q", _domain(c), "-silent"], parse="lines"),

    # --- URL / archive collection -------------------------------------------
    Row("waymore", S_URLS,
        lambda c: ["waymore", "-i", _domain(c), "-mode", "U", "-oU", "/dev/stdout"],
        parse="urls", timeout=600),
    Row("gauplus", S_URLS, lambda c: ["gauplus", "-t", "20", "-subs", _domain(c)],
        parse="urls", timeout=600),
    Row("xurlfind3r", S_URLS, lambda c: ["xurlfind3r", "-d", _domain(c), "-s"], parse="urls"),
    Row("cariddi", S_URLS, lambda c: ["cariddi", "-plain"], parse="urls",
        stdin=lambda c: "\n".join(_live_urls(c))),
    Row("photon", S_URLS, lambda c: ["photon", "-u", (_live_urls(c) or [""])[0],
                                     "-l", "2", "--stdout", "urls"], parse="urls"),

    # --- JavaScript ----------------------------------------------------------
    Row("jsleak", S_JS, lambda c: ["jsleak", "-l", "-s"], parse="lines",
        stdin=lambda c: "\n".join(ctx_js(c))),
    Row("jsubfinder", S_JS, lambda c: ["jsubfinder", "search", "-s"], parse="lines",
        stdin=lambda c: "\n".join(ctx_js(c))),

    # --- more URL discovery --------------------------------------------------
    # github-endpoints finds paths committed to a domain's public GitHub code —
    # endpoints that no crawl or archive will ever surface. Needs GITHUB_TOKEN.
    Row("github-endpoints", S_URLS,
        lambda c: ["github-endpoints", "-d", _domain(c)], parse="urls", timeout=300),
    # gf tags collected URLs by likely vuln class so the injectable ones survive
    # deduplication and reach the OWASP stage first. Harmless where ~/.gf is not
    # set up (it simply returns nothing).
    Row("gf", S_URLS, lambda c: ["gf", "xss"], parse="urls", stdin=_urls_text, timeout=120),
    Row("gf", S_URLS, lambda c: ["gf", "sqli"], parse="urls", stdin=_urls_text, timeout=120),
    Row("gf", S_URLS, lambda c: ["gf", "ssrf"], parse="urls", stdin=_urls_text, timeout=120),
    Row("gf", S_URLS, lambda c: ["gf", "redirect"], parse="urls", stdin=_urls_text, timeout=120),

    # --- parameters ----------------------------------------------------------
    Row("x8", S_PARAMS, lambda c: ["x8", "-u", (_live_urls(c) or [""])[0],
                                   "-w", c.get("param_wordlist", ""), "-O", "json"],
        parse="lines", timeout=420),

    # --- content -------------------------------------------------------------
    Row("gobuster", S_CONTENT,
        lambda c: ["gobuster", "dir", "-u", (_live_urls(c) or [""])[0],
                   "-w", c.get("content_wordlist", ""), "-q", "--no-error"],
        parse="lines", timeout=420),
    Row("dirb", S_CONTENT,
        lambda c: ["dirb", (_live_urls(c) or [""])[0], c.get("content_wordlist", ""), "-S", "-w"],
        parse="lines", timeout=420),

    # --- takeover ------------------------------------------------------------
    Row("dnsReaper", S_TAKEOVER,
        lambda c: ["dnsReaper", "file", "--filename", c.get("hosts_file", ""), "--out-format", "json"],
        parse="vuln", timeout=420),
    Row("tko-subs", S_TAKEOVER,
        lambda c: ["tko-subs", "-domains", c.get("hosts_file", "")], parse="vuln"),

    # --- vulnerability / injection ------------------------------------------
    Row("jaeles", S_VULN, lambda c: ["jaeles", "scan", "-U", "-", "--no-db"],
        parse="vuln", stdin=_urls_text, timeout=900),
    Row("kxss", S_VULN, lambda c: ["kxss"], parse="vuln", stdin=_urls_text),
    Row("Gxss", S_VULN, lambda c: ["Gxss", "-c", "20"], parse="vuln", stdin=_urls_text),
    Row("nikto", S_CMS, lambda c: ["nikto", "-h", (_live_urls(c) or [""])[0],
                                   "-Tuning", "1234567", "-nointeractive"],
        parse="vuln", timeout=600),
    Row("wpscan", S_CMS, lambda c: ["wpscan", "--url", (_live_urls(c) or [""])[0],
                                    "--no-banner", "--format", "json",
                                    "--random-user-agent"], parse="vuln", timeout=600),
    Row("droopescan", S_CMS, lambda c: ["droopescan", "scan", "drupal", "-u",
                                        (_live_urls(c) or [""])[0]], parse="vuln", timeout=420),

    # --- TLS -----------------------------------------------------------------
    Row("sslyze", S_TLS, lambda c: ["sslyze", "--quiet", "--json_out=-",
                                    c.get("apex_host", "")], parse="vuln", timeout=300),
    Row("testssl.sh", S_TLS, lambda c: ["testssl.sh", "--quiet", "--fast",
                                        "--severity", "MEDIUM", c.get("apex_host", "")],
        parse="vuln", timeout=600),

    # --- cloud ---------------------------------------------------------------
    Row("s3scanner", S_CLOUD, lambda c: ["s3scanner", "-bucket", _domain(c).split(".")[0]],
        parse="vuln"),

    # --- API -----------------------------------------------------------------
    Row("graphw00f", S_API, lambda c: ["graphw00f", "-f", "-t",
                                       (_live_urls(c) or [""])[0]], parse="vuln"),
)


def ctx_js(ctx) -> list:
    return list(ctx.get("js_urls", ()))[:2000]


def _parse(kind: str, out: str, domain: str) -> set[str]:
    """Turn raw stdout into the set of strings a stage cares about."""
    found: set[str] = set()
    if not out:
        return found
    if kind == "urls":
        found |= set(URL_RE.findall(out))
    elif kind == "hosts":
        for line in out.splitlines():
            candidate = line.strip().lower().lstrip("*.").split()[0] if line.strip() else ""
            candidate = candidate.rstrip(".,;")
            if candidate and HOST_RE.match(candidate):
                if not domain or candidate == domain or candidate.endswith("." + domain):
                    found.add(candidate)
    elif kind == "json_urls":
        for line in out.splitlines():
            try:
                found.add(json.loads(line).get("url", ""))
            except Exception:
                continue
        found.discard("")
    else:  # "lines" / "vuln" — caller interprets
        found |= {l.strip() for l in out.splitlines() if l.strip()}
    return found


def available(inv: ToolInventory, stage: str) -> list[str]:
    """Which extra tools for this stage are actually installed."""
    return [r.tool for r in ROWS if r.stage == stage and inv.has(r.tool)]


def run_stage(stage: str, ctx: dict, inv: ToolInventory, log,
              stop: threading.Event) -> set[str]:
    """Run every installed tool registered for ``stage`` and merge the output.

    Tools disagree — that is the entire reason to run more than one — so the
    results are unioned rather than taking the first non-empty answer.
    """
    rows = [r for r in ROWS if r.stage == stage and inv.has(r.tool)]
    if not rows:
        return set()

    log("info", f"Extra {stage} tools: {', '.join(r.tool for r in rows)}")
    merged: set[str] = set()
    domain = ctx.get("domain", "")

    for row in rows:
        if stop.is_set():
            break
        try:
            argv = row.argv(ctx)
        except Exception:
            continue
        if not argv or not argv[0] or any(a == "" for a in argv):
            log("warn", f"  {row.tool}: skipped (missing input)")
            continue

        payload = row.stdin(ctx) if row.stdin else None
        if row.stdin is not None and not payload:
            log("warn", f"  {row.tool}: skipped (nothing to feed it)")
            continue

        code, out, err = run(argv, timeout=row.timeout, input_text=payload)
        if code not in (0, 124) and not out:
            log("warn", f"  {row.tool} failed: {(err or '').strip()[:110]}")
            continue

        produced = _parse(row.parse, out, domain if row.parse == "hosts" else "")
        if produced:
            log("info", f"  {row.tool}: {len(produced)} results")
            merged |= produced
        else:
            log("info", f"  {row.tool}: nothing")
    return merged


def write_hosts_file(hosts) -> str:
    """Some tools only accept a file path; give them a temporary one."""
    handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         prefix="smarthunt-hosts-")
    handle.write("\n".join(sorted(hosts)))
    handle.close()
    return handle.name
