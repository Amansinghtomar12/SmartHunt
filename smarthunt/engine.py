"""Scan orchestration.

:class:`Scanner` runs a staged pipeline on a background thread and streams
events back to whatever front-end is attached (the Tkinter GUI, or the CLI).

Two profiles exist, matching the two target modes:

``domain``
    One host, deep.  Crawl it, pull every JavaScript file, mine those files for
    endpoints/parameters/secrets, discover content, and test what was found.

``wildcard``
    ``*.example.com`` — go wide first.  Every subdomain source and tool, then
    resolve, probe, port-scan, check for takeovers, and only then go deep on
    the live hosts.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict

from . import jsrecon, modules, wordlists
from .modules import Finding, HostResult, SEVERITY_RANK
from .tools import ToolInventory, detect_tools

MODE_DOMAIN = "domain"
MODE_WILDCARD = "wildcard"

#: Stage keys in execution order, with the modes each applies to.
STAGES = [
    ("subdomains", "Subdomain Enumeration", (MODE_WILDCARD,)),
    ("resolve", "DNS Resolution", (MODE_DOMAIN, MODE_WILDCARD)),
    ("ports", "Port Scanning", (MODE_DOMAIN, MODE_WILDCARD)),
    ("http", "HTTP Probing", (MODE_DOMAIN, MODE_WILDCARD)),
    ("tech", "Technology Fingerprinting", (MODE_DOMAIN, MODE_WILDCARD)),
    ("takeover", "Subdomain Takeover", (MODE_WILDCARD,)),
    ("urls", "URL / Endpoint Collection", (MODE_DOMAIN, MODE_WILDCARD)),
    ("js", "JavaScript Gathering & Analysis", (MODE_DOMAIN, MODE_WILDCARD)),
    ("params", "Parameter Discovery", (MODE_DOMAIN, MODE_WILDCARD)),
    ("content", "Content Discovery", (MODE_DOMAIN, MODE_WILDCARD)),
    ("vulns", "Vulnerability Checks", (MODE_DOMAIN, MODE_WILDCARD)),
    ("screenshot", "Screenshots", (MODE_DOMAIN, MODE_WILDCARD)),
]

STAGE_TITLES = {key: title for key, title, _ in STAGES}

#: Stages enabled by default per mode.
DEFAULT_ENABLED = {
    MODE_DOMAIN: {"resolve", "http", "tech", "urls", "js", "params", "content", "vulns"},
    MODE_WILDCARD: {"subdomains", "resolve", "http", "tech", "takeover", "urls",
                    "js", "params", "content", "vulns"},
}

_DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def normalize_target(raw: str) -> tuple[str, str]:
    """Turn user input into ``(mode, apex_domain)``.

    ``*.example.com`` or ``.example.com`` -> wildcard mode.
    ``example.com`` or ``https://example.com/path`` -> domain mode.
    Raises :class:`ValueError` on anything that isn't a domain.
    """
    target = (raw or "").strip().lower()
    if not target:
        raise ValueError("Target is empty")
    target = re.sub(r"^https?://", "", target)
    target = target.split("/")[0].split("?")[0]
    target = target.split("@")[-1].split(":")[0]

    mode = MODE_DOMAIN
    if target.startswith("*."):
        mode, target = MODE_WILDCARD, target[2:]
    elif target.startswith("."):
        mode, target = MODE_WILDCARD, target[1:]

    target = target.strip(".")
    if not target or not _DOMAIN_RE.match(target):
        raise ValueError(f"'{raw}' is not a valid domain")
    return mode, target


@dataclass
class ScanConfig:
    """Everything the GUI can tune before pressing Start."""

    target: str = ""
    mode: str = MODE_DOMAIN
    enabled_stages: set[str] = field(default_factory=set)
    threads: int = 40
    timeout: int = 10
    include_subdomains: bool = True      # for URL collection in domain mode
    bruteforce_subdomains: bool = True
    crawl_depth: int = 2
    max_pages: int = 300
    max_js_files: int = 400
    ports: list[int] = field(default_factory=list)
    subdomain_wordlist: str = ""         # path to a file; empty = built-in
    content_wordlist: str = ""
    nuclei_severity: str = "low,medium,high,critical"
    output_dir: str = ""
    authorized: bool = False             # explicit user confirmation

    def wordlist_lines(self, path: str) -> list[str]:
        if not path or not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except Exception:
            return []


@dataclass
class ScanResults:
    """Everything a scan produced."""

    target: str = ""
    mode: str = ""
    started: float = 0.0
    finished: float = 0.0
    subdomains: list[str] = field(default_factory=list)
    resolved: dict = field(default_factory=dict)
    hosts: list[dict] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    params: dict = field(default_factory=dict)
    secrets: list[dict] = field(default_factory=list)
    content: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return (self.finished or time.time()) - self.started

    def stats(self) -> dict:
        crit = sum(1 for f in self.findings if f["severity"] == "critical")
        high = sum(1 for f in self.findings if f["severity"] == "high")
        return {
            "Subdomains": len(self.subdomains),
            "Live hosts": len(self.hosts),
            "URLs": len(self.urls),
            "JS files": len(self.js_files),
            "Endpoints": len(self.js_endpoints),
            "Parameters": len(self.params.get("names", [])),
            "Secrets": len(self.secrets),
            "Findings": len(self.findings),
            "Critical/High": crit + high,
        }

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)


class Scanner:
    """Runs a :class:`ScanConfig` on a background thread."""

    def __init__(self, config: ScanConfig, on_log=None, on_stage=None,
                 on_progress=None, on_done=None, inventory: ToolInventory | None = None):
        self.config = config
        self.inv = inventory or detect_tools()
        self.results = ScanResults(target=config.target, mode=config.mode)
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._on_log = on_log or (lambda level, msg: None)
        self._on_stage = on_stage or (lambda key, state: None)
        self._on_progress = on_progress or (lambda done, total: None)
        self._on_done = on_done or (lambda results, error: None)
        self.session = modules.make_session()

    # --- control ----------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self.stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="smarthunt-scan")
        self._thread.start()

    def stop(self):
        self.stop_event.set()
        self.pause_event.clear()

    def pause(self):
        self.pause_event.set()

    def resume(self):
        self.pause_event.clear()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def log(self, level, message):
        self._on_log(level, message)

    def _wait_if_paused(self):
        while self.pause_event.is_set() and not self.stop_event.is_set():
            time.sleep(0.2)

    def _enabled(self, key):
        return key in self.config.enabled_stages

    # --- pipeline ---------------------------------------------------------
    def _run(self):
        cfg = self.config
        res = self.results
        res.started = time.time()
        error = None

        planned = [k for k, _, modes in STAGES if cfg.mode in modes and self._enabled(k)]
        total = len(planned)
        done = 0

        try:
            self.log("info", "=" * 68)
            self.log("info", f"SmartHunt starting — target: {cfg.target}  mode: {cfg.mode}")
            self.log("info", self.inv.summary())
            self.log("info", f"Stages: {', '.join(STAGE_TITLES[k] for k in planned) or 'none'}")
            self.log("info", "=" * 68)
            res.tools_used = sorted(self.inv.available)

            hosts: set[str] = {cfg.target}
            live: dict[str, HostResult] = {}
            resolved: dict[str, tuple[list[str], str]] = {}
            urls: set[str] = set()
            content_hits: list[dict] = []
            findings: list[Finding] = []

            def begin(key):
                self._wait_if_paused()
                self._on_stage(key, "running")
                self.log("stage", f"▶ {STAGE_TITLES[key]}")

            def end(key, skipped=False):
                nonlocal done
                done += 1
                self._on_stage(key, "skipped" if skipped else "done")
                self._on_progress(done, total)

            # --- 1. subdomain enumeration (wildcard only) ------------------
            if "subdomains" in planned and not self.stop_event.is_set():
                begin("subdomains")
                wl = cfg.wordlist_lines(cfg.subdomain_wordlist) or wordlists.SUBDOMAINS
                hosts = modules.enumerate_subdomains(
                    cfg.target, self.inv, wl, self.log, self.stop_event,
                    threads=cfg.threads, use_bruteforce=cfg.bruteforce_subdomains)
                res.subdomains = sorted(hosts)
                self.log("info", f"✓ {len(hosts)} unique subdomains")
                end("subdomains")
            else:
                res.subdomains = sorted(hosts)

            # --- 2. DNS resolution ------------------------------------------
            if "resolve" in planned and not self.stop_event.is_set():
                begin("resolve")
                resolved = modules.resolve_hosts(hosts, self.inv, self.log,
                                                 self.stop_event, threads=cfg.threads)
                res.resolved = {h: {"ips": v[0], "cname": v[1]} for h, v in resolved.items()}
                if resolved:
                    hosts = set(resolved)
                end("resolve")

            # --- 3. port scanning -------------------------------------------
            port_map: dict[str, list[int]] = {}
            if "ports" in planned and not self.stop_event.is_set():
                begin("ports")
                port_map = modules.scan_ports(sorted(hosts)[:500], cfg.ports, self.inv,
                                              self.log, self.stop_event)
                end("ports")

            # --- 4. HTTP probing --------------------------------------------
            if "http" in planned and not self.stop_event.is_set():
                begin("http")
                live = modules.probe_http(sorted(hosts), self.inv, self.log,
                                          self.stop_event, self.session, threads=cfg.threads)
                end("http")
            if not live and not self.stop_event.is_set():
                # Keep going with a synthetic entry so later stages still have a seed.
                live = {cfg.target: HostResult(host=cfg.target, url=f"https://{cfg.target}")}

            for host, hr in live.items():
                if host in resolved:
                    hr.ips, hr.cname = resolved[host]
                hr.ports = port_map.get(host, [])

            # --- 5. technology fingerprinting -------------------------------
            if "tech" in planned and not self.stop_event.is_set():
                begin("tech")
                modules.fingerprint(live, self.log, self.stop_event, self.session)
                end("tech")

            # --- 6. subdomain takeover --------------------------------------
            if "takeover" in planned and not self.stop_event.is_set():
                begin("takeover")
                findings += modules.check_takeover(resolved, live, self.inv, self.log,
                                                   self.stop_event, self.session)
                end("takeover")

            # --- 7. URL / endpoint collection --------------------------------
            if "urls" in planned and not self.stop_event.is_set():
                begin("urls")
                urls = modules.collect_urls(
                    cfg.target, live, self.inv, self.log, self.stop_event, self.session,
                    include_subs=(cfg.mode == MODE_WILDCARD or cfg.include_subdomains),
                    crawl_depth=cfg.crawl_depth, max_pages=cfg.max_pages)
                res.urls = sorted(urls)
                end("urls")

            # --- 8. JavaScript gathering & analysis --------------------------
            if "js" in planned and not self.stop_event.is_set():
                begin("js")
                seeds = [hr.url or hr.host for hr in live.values()]
                js_urls = jsrecon.collect_js_urls(
                    seeds, self.inv, self.log, self.stop_event, self.session,
                    extra_urls=urls, threads=cfg.threads)
                res.js_files = sorted(js_urls)
                analysis = jsrecon.analyze_js(
                    js_urls, self.inv, self.log, self.stop_event, self.session,
                    base_domain=cfg.target, threads=max(5, cfg.threads // 3),
                    max_files=cfg.max_js_files)
                res.js_endpoints = analysis["endpoints"]
                res.secrets = analysis["secrets"]
                for secret in analysis["secrets"]:
                    findings.append(Finding(
                        host=cfg.target, name=f"Secret in JS: {secret['type']}",
                        severity=secret["severity"],
                        detail=f"{secret['value']}  ({secret['source']})",
                        source="jsrecon"))
                # JS-derived endpoints feed the URL pool for later stages
                for endpoint in analysis["endpoints"]:
                    if endpoint.startswith("http"):
                        urls.add(endpoint)
                res.urls = sorted(urls)
                end("js")

            # --- 9. parameter discovery ---------------------------------------
            if "params" in planned and not self.stop_event.is_set():
                begin("params")
                res.params = modules.discover_params(cfg.target, urls, self.inv,
                                                     self.log, self.stop_event)
                end("params")

            # --- 10. content discovery -----------------------------------------
            if "content" in planned and not self.stop_event.is_set():
                begin("content")
                paths = cfg.wordlist_lines(cfg.content_wordlist) or wordlists.CONTENT_PATHS
                content_hits = modules.discover_content(
                    live, paths, self.inv, self.log, self.stop_event, self.session,
                    threads=cfg.threads, wordlist_path=cfg.content_wordlist)
                res.content = content_hits
                end("content")

            # --- 11. vulnerability checks --------------------------------------
            if "vulns" in planned and not self.stop_event.is_set():
                begin("vulns")
                findings += modules.check_vulns(
                    live, content_hits, urls, self.inv, self.log, self.stop_event,
                    self.session, nuclei_severity=cfg.nuclei_severity)
                end("vulns")

            # --- 12. screenshots -------------------------------------------------
            if "screenshot" in planned and not self.stop_event.is_set():
                begin("screenshot")
                outdir = os.path.join(cfg.output_dir or ".", "screenshots")
                os.makedirs(outdir, exist_ok=True)
                modules.screenshot(live, self.inv, self.log, self.stop_event, outdir)
                end("screenshot")

            res.hosts = [hr.as_dict() for hr in sorted(live.values(), key=lambda h: h.host)]
            findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 5))
            res.findings = [f.as_dict() for f in findings]

        except Exception as exc:  # pragma: no cover - surfaced in the GUI
            import traceback
            error = exc
            self.log("error", f"Scan failed: {exc}")
            self.log("error", traceback.format_exc(limit=4))
        finally:
            res.finished = time.time()
            if self.stop_event.is_set():
                self.log("warn", f"Scan stopped after {res.duration:.1f}s")
            elif error is None:
                self.log("info", "=" * 68)
                self.log("info", f"Scan complete in {res.duration:.1f}s — " +
                         ", ".join(f"{k}: {v}" for k, v in res.stats().items()))
                self.log("info", "=" * 68)
            self._on_done(res, error)
