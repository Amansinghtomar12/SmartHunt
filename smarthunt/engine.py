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

from . import accesscontrol, ai, auth, cve, jsrecon, modules, owasp, triage, wordlists
from .modules import Finding, HostResult, SEVERITY_RANK
from .tools import ToolInventory, detect_tools, run as tools_run

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
    ("endpoints", "API Endpoint Verification", (MODE_DOMAIN, MODE_WILDCARD)),
    ("params", "Parameter Discovery", (MODE_DOMAIN, MODE_WILDCARD)),
    ("content", "Content Discovery", (MODE_DOMAIN, MODE_WILDCARD)),
    ("vulns", "Vulnerability Checks", (MODE_DOMAIN, MODE_WILDCARD)),
    ("owasp", "OWASP Top 10 Testing", (MODE_DOMAIN, MODE_WILDCARD)),
    ("cve", "Known CVE Matching", (MODE_DOMAIN, MODE_WILDCARD)),
    ("accesscontrol", "Access Control / IDOR (needs 2 sessions)",
     (MODE_DOMAIN, MODE_WILDCARD)),
    ("screenshot", "Screenshots", (MODE_DOMAIN, MODE_WILDCARD)),
]

STAGE_TITLES = {key: title for key, title, _ in STAGES}

#: Stages enabled by default per mode.
DEFAULT_ENABLED = {
    MODE_DOMAIN: {"resolve", "http", "tech", "urls", "js", "endpoints", "params",
                  "content", "vulns", "owasp", "cve", "accesscontrol"},
    MODE_WILDCARD: {"subdomains", "resolve", "http", "tech", "takeover", "urls",
                    "js", "endpoints", "params", "content", "vulns", "owasp",
                    "cve", "accesscontrol"},
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
    collaborator: str = ""               # host that observes SSRF callbacks
    cve_online: bool = False             # also query OSV/NVD, slower and rate-limited
    use_sqlmap: bool = True              # only on an already-confirmed injection
    exhaustive: bool = False             # loop discovery until nothing new appears
    max_rounds: int = 4                  # safety stop for the exhaustive loop
    # --- authenticated testing (all optional) ---------------------------
    auth_headers: str = ""               # pasted raw header block for Account A
    auth_cookies: str = ""               # or just a Cookie: value
    auth_bearer: str = ""                # or just a token
    auth_check_url: str = ""             # a URL that requires being logged in
    auth_check_marker: str = ""          # text present only when logged in
    victim_headers: str = ""             # Account B — enables IDOR proof
    victim_cookies: str = ""
    victim_bearer: str = ""
    # --- AI assist (optional, off by default) ----------------------------
    ai_enabled: bool = False             # opt-in: scan metadata leaves the machine
    ai_model: str = ""                   # blank = the module default
    ai_advice: bool = True               # let it retune the scan mid-run
    ai_report: bool = True               # let it write the final report
    ai_budget: int = 8                   # hard cap on model calls per scan

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
    api_endpoints: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    report: dict = field(default_factory=dict)   # the single triaged finding
    tools_used: list[str] = field(default_factory=list)
    ai: dict = field(default_factory=dict)       # what the AI assist did, if enabled

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
            "Live APIs": sum(1 for e in self.api_endpoints if e.get("api")),
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
        # self.session is what every stage uses. When credentials are supplied
        # it carries them, so crawling, JS collection, content discovery and the
        # OWASP checks all run as a logged-in user rather than stopping at the
        # login wall. anon_session stays clean for the "is this actually
        # public?" comparison.
        self.anon_session = modules.make_session()
        self.attacker = auth.build_profile(
            "attacker A", config.auth_headers, config.auth_cookies,
            config.auth_bearer, config.auth_check_url, config.auth_check_marker)
        self.victim = auth.build_profile(
            "victim B", config.victim_headers, config.victim_cookies,
            config.victim_bearer, config.auth_check_url, config.auth_check_marker)

        self.session = (auth.make_authenticated_session(self.attacker, modules.make_session)
                        if self.attacker.configured else self.anon_session)
        self.victim_session = (auth.make_authenticated_session(self.victim, modules.make_session)
                               if self.victim.configured else None)
        self._wildcard_ips = None   # cached across exhaustive rounds
        # Built lazily inside the scan thread so a missing provider is reported
        # in the scan log rather than at construction time.
        self.ai = None
        self.ai_paths: set[str] = set()   # extra content-discovery paths it asked for

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

    def _apply_exhaustive_limits(self):
        """Raise the per-stage caps that exist to keep a normal scan quick.

        These caps are the difference between "a scan" and "the scan" — the
        crawler stops at 300 pages, JS analysis at 400 files. Exhaustive mode
        is the user saying they want coverage over wall-clock, so the ceilings
        go up rather than away: an unbounded crawl on a large wildcard scope
        never terminates, which is not the same thing as thorough.
        """
        cfg = self.config
        if not cfg.exhaustive:
            return
        cfg.max_pages = max(cfg.max_pages, 5000)
        cfg.max_js_files = max(cfg.max_js_files, 4000)
        cfg.crawl_depth = max(cfg.crawl_depth, 4)
        cfg.include_subdomains = True
        cfg.bruteforce_subdomains = True
        self.log("info", f"Exhaustive mode: crawl depth {cfg.crawl_depth}, "
                         f"{cfg.max_pages} pages, {cfg.max_js_files} JS files, "
                         f"up to {cfg.max_rounds} discovery rounds")

    def _verify_sessions(self):
        """Prove the supplied sessions are live before the scan relies on them.

        A stale cookie does not announce itself: the app just serves the login
        page with HTTP 200, and every finding afterwards is quietly about that
        login page. Better to say so once, loudly, at the start.
        """
        for profile, session in ((self.attacker, self.session),
                                 (self.victim, self.victim_session)):
            if not profile.configured:
                continue
            ok, detail = auth.verify(profile, session, self.log)
            level = "info" if ok else "warn"
            self.log(level, f"Session [{profile.label}] {detail}")
            if not ok and profile.check_url:
                self.log("warn", "  results from this session may just be the "
                                 "login page — re-copy the session and retry")

    def _recurse_hosts(self, cfg, res, hosts, urls, live) -> set:
        """Mine everything found so far for hostnames we have not seen yet.

        Three sources, because they surface different things: hostnames sitting
        in collected URLs, hostnames referenced inside JavaScript, and a fresh
        permutation pass seeded by the subdomains discovered since round one.
        """
        found = set(hosts)
        apex = cfg.target

        # 1. hostnames embedded in every URL we have collected
        for url in urls:
            try:
                netloc = re.sub(r":\d+$", "", (url.split("//", 1)[-1].split("/")[0]).lower())
            except Exception:
                continue
            if netloc and (netloc == apex or netloc.endswith("." + apex)):
                found.add(netloc)

        # 2. hostnames named inside JS endpoints
        for endpoint in res.js_endpoints:
            for match in re.finditer(r"https?://([a-z0-9.\-]+)", endpoint, re.I):
                host = match.group(1).lower()
                if host == apex or host.endswith("." + apex):
                    found.add(host)

        # 3. permutation seeded by what this scan has actually seen, which is a
        #    better wordlist than any static list for this particular target
        if cfg.mode == MODE_WILDCARD and cfg.bruteforce_subdomains and len(found) > 1:
            try:
                permuted = modules._permute(apex, found, self.inv, self.log,
                                            self.stop_event, cfg.threads)
                # Same wildcard guard as the first pass — without it a
                # wildcard-DNS target makes every round "discover" more hosts
                # and the loop never converges.
                if self._wildcard_ips is None:
                    self._wildcard_ips = modules.detect_wildcard(
                        apex, self.log, self.stop_event)
                found |= modules._drop_wildcard_hits(
                    permuted, self._wildcard_ips, self.log, self.stop_event, cfg.threads)
            except Exception as exc:
                self.log("warn", f"  permutation round failed: {exc}")
        return found

    def _confirm_with_sqlmap(self, owasp_findings, findings):
        """Run sqlmap only where injection is already proven.

        sqlmap is intrusive and slow, so pointing it at every parameter is both
        rude to the target and wasteful. Running it solely against a parameter
        whose database error we already captured turns a proven injection into
        a confirmed one, with the backend named.
        """
        cfg = self.config
        candidates = [f for f in owasp_findings if "sql injection" in f.name.lower()]
        if not (candidates and cfg.use_sqlmap and self.inv.has("sqlmap")):
            return
        for finding in candidates[:3]:
            if self.stop_event.is_set():
                break
            self.log("info", f"Confirming with sqlmap: {finding.endpoint}")
            code, out, _ = tools_run(
                ["sqlmap", "-u", finding.endpoint, "--batch", "--level=1", "--risk=1",
                 "--technique=B", "--answers=follow=N", "--disable-coloring"],
                timeout=600)
            if code in (0, 124) and out and "is vulnerable" in out.lower():
                finding.detail += "  [confirmed by sqlmap]"
                finding.confidence = "high"
                self.log("found", f"  sqlmap confirmed injection on {finding.param}")

    # --- AI assist --------------------------------------------------------
    def _ai_context(self, phase, live, urls, findings) -> dict:
        """The scan's own numbers — no credentials, no response bodies."""
        cfg = self.config
        severities: dict[str, int] = {}
        for finding in findings:
            severities[finding.severity] = severities.get(finding.severity, 0) + 1
        return {
            "phase": phase,
            "scope": (f"*.{cfg.target}" if cfg.mode == MODE_WILDCARD else cfg.target),
            "mode": cfg.mode,
            "counts": {
                "subdomains": len(self.results.subdomains),
                "live_hosts": len(live),
                "urls": len(urls),
                "js_files": len(self.results.js_files),
                "js_endpoints": len(self.results.js_endpoints),
                "verified_api_endpoints": sum(1 for e in self.results.api_endpoints
                                              if e.get("api")),
                "parameters": len(self.results.params.get("names", [])),
                "findings_by_severity": severities,
            },
            "settings": {key: getattr(cfg, key) for key in ai.TUNABLE},
            "live_host_sample": sorted(live)[:40],
            "technologies": sorted({tech for hr in live.values()
                                    for tech in (hr.tech or [])})[:30],
            "tools_installed": sorted(self.inv.available),
            "elapsed_seconds": int(time.time() - self.results.started),
        }

    def _ai_checkpoint(self, phase, live, urls, findings):
        """Let the assistant retune the scan, inside fixed limits.

        Only settings on :data:`smarthunt.ai.TUNABLE` are applied, each clamped
        to the range the UI already permits, and suggested hostnames are dropped
        unless they sit inside the authorised scope. The assistant cannot reach
        the evidence gate, the authorisation flag or the target.
        """
        if not (self.ai and self.config.ai_advice) or self.stop_event.is_set():
            return
        self.log("stage", f"▶ AI assist — reviewing progress ({phase})")
        advice = self.ai.advise(self._ai_context(phase, live, urls, findings),
                                self.config.target)
        if not advice:
            return

        if advice["assessment"]:
            self.log("info", f"  {advice['assessment']}")
        was_exhaustive = self.config.exhaustive
        for adjustment in advice["adjustments"]:
            setting, value = adjustment["setting"], adjustment["value"]
            before = getattr(self.config, setting)
            if before == value:
                continue
            setattr(self.config, setting, value)
            self.log("found", f"  adjusted {setting}: {before} → {value}"
                              + (f" ({adjustment['why']})" if adjustment["why"] else ""))
        if self.config.exhaustive and not was_exhaustive:
            # Switching exhaustive on has to bring its raised caps with it, or
            # the extra rounds run against the quick-scan ceilings.
            self._apply_exhaustive_limits()
        if advice["focus_paths"]:
            fresh = set(advice["focus_paths"]) - self.ai_paths
            self.ai_paths |= fresh
            if fresh:
                self.log("info", f"  queued {len(fresh)} extra path(s) for content "
                                 f"discovery")
        for note in advice["notes"]:
            self.log("info", f"  note: {note}")

        new_hosts = [h for h in advice["focus_hosts"] if h not in live]
        if new_hosts and not self.stop_event.is_set():
            self.log("info", f"  probing {len(new_hosts)} suggested in-scope host(s)")
            live.update(modules.probe_http(sorted(new_hosts), self.inv, self.log,
                                           self.stop_event, self.session,
                                           threads=self.config.threads))

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
            self.log("info", auth.summarise(self.attacker, self.victim))
            self._verify_sessions()
            self._apply_exhaustive_limits()
            if cfg.ai_enabled:
                self.ai = ai.Assistant.create(self.log, model=cfg.ai_model,
                                              budget=cfg.ai_budget)

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

            # The first checkpoint: the live surface is known but nothing deep
            # has run yet, so a depth or breadth adjustment still changes the
            # outcome. On a large wildcard scope this is where the right crawl
            # settings stop being a guess.
            self._ai_checkpoint("reconnaissance complete", live, urls, findings)

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

            # --- 8b. verify JS-derived endpoints against every live host ------
            # Reading a bundle yields path strings; this is where they become
            # real, callable endpoints. In wildcard mode each path is tried on
            # every live subdomain, because staging frequently exposes an API
            # that production does not.
            if "endpoints" in planned and not self.stop_event.is_set():
                begin("endpoints")
                res.api_endpoints = jsrecon.verify_endpoints(
                    res.js_endpoints, live, self.log, self.stop_event, self.session,
                    threads=max(5, cfg.threads // 2))
                for hit in res.api_endpoints:
                    urls.add(hit["url"])
                res.urls = sorted(urls)
                end("endpoints")

            # --- 9. parameter discovery ---------------------------------------
            if "params" in planned and not self.stop_event.is_set():
                begin("params")
                res.params = modules.discover_params(cfg.target, urls, self.inv,
                                                     self.log, self.stop_event)
                end("params")

            # A second checkpoint, now that the JavaScript has been read: what
            # the bundles named is the best signal for which paths are worth
            # requesting, and content discovery has not run yet.
            self._ai_checkpoint("endpoints mined, before content discovery",
                                live, urls, findings)

            # --- 10. content discovery -----------------------------------------
            if "content" in planned and not self.stop_event.is_set():
                begin("content")
                paths = cfg.wordlist_lines(cfg.content_wordlist) or wordlists.CONTENT_PATHS
                if self.ai_paths:
                    paths = list(dict.fromkeys(list(paths) + sorted(self.ai_paths)))
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

            # --- 11b. OWASP Top 10 ------------------------------------------------
            if "owasp" in planned and not self.stop_event.is_set():
                begin("owasp")
                fuzz_urls = modules.build_fuzz_urls(urls, self.inv, self.log,
                                                    self.stop_event, marker="1")
                owasp_findings = owasp.run_checks(
                    live, fuzz_urls or sorted(urls),
                    [e["url"] for e in res.api_endpoints],
                    res.js_files, self.log, self.stop_event, self.session,
                    threads=max(5, cfg.threads // 4),
                    collaborator=cfg.collaborator)
                findings += owasp_findings
                self._confirm_with_sqlmap(owasp_findings, findings)
                end("owasp")

            # --- 11b2. known CVE matching ----------------------------------------
            if "cve" in planned and not self.stop_event.is_set():
                begin("cve")
                findings += cve.check(list(live.values()), res.js_files, self.log,
                                      self.stop_event, online=cfg.cve_online)
                end("cve")

            # --- 11c. access control (needs both sessions) -----------------------
            if "accesscontrol" in planned and not self.stop_event.is_set():
                begin("accesscontrol")
                findings += accesscontrol.run_checks(
                    urls, res.api_endpoints, self.session, self.victim_session,
                    self.anon_session, self.log, self.stop_event,
                    threads=max(2, cfg.threads // 8))
                end("accesscontrol")

            # --- 12. screenshots -------------------------------------------------
            if "screenshot" in planned and not self.stop_event.is_set():
                begin("screenshot")
                outdir = os.path.join(cfg.output_dir or ".", "screenshots")
                os.makedirs(outdir, exist_ok=True)
                modules.screenshot(live, self.inv, self.log, self.stop_event, outdir)
                end("screenshot")

            # --- exhaustive: recurse until a round finds nothing new ---------
            # Each round's discoveries are the next round's seeds: a subdomain
            # found by permutation can host JS naming another subdomain, whose
            # bundle names an API on a third. One pass stops at the first hop;
            # this keeps going until the frontier is empty.
            if cfg.exhaustive and not self.stop_event.is_set():
                # A while loop rather than range(): cfg.max_rounds can be raised
                # by an AI checkpoint between rounds, and a range would have
                # been frozen at the old value — the log would report an
                # adjustment that never took effect.
                round_no = 1
                while round_no < cfg.max_rounds:
                    round_no += 1
                    if self.stop_event.is_set():
                        break
                    before = (len(hosts), len(urls), len(live))
                    self.log("stage", f"▶ Exhaustive round {round_no}/{cfg.max_rounds}")
                    # Between rounds is where retuning pays for itself: the
                    # previous round's yield says whether to push further or
                    # stop, and cfg.max_rounds is one of the settings on offer.
                    self._ai_checkpoint(f"exhaustive round {round_no} starting",
                                        live, urls, findings)

                    new_hosts = self._recurse_hosts(cfg, res, hosts, urls, live)
                    fresh = new_hosts - hosts
                    if fresh:
                        self.log("found", f"  round {round_no}: {len(fresh)} new hosts")
                        hosts |= fresh
                        newly_live = modules.probe_http(
                            sorted(fresh), self.inv, self.log, self.stop_event,
                            self.session, threads=cfg.threads)
                        live.update(newly_live)

                    if "urls" in planned and not self.stop_event.is_set():
                        more = modules.collect_urls(
                            cfg.target, live, self.inv, self.log, self.stop_event,
                            self.session, include_subs=True,
                            crawl_depth=cfg.crawl_depth, max_pages=cfg.max_pages)
                        urls |= more

                    if "js" in planned and not self.stop_event.is_set():
                        seeds = [hr.url or hr.host for hr in live.values()]
                        js_urls = jsrecon.collect_js_urls(
                            seeds, self.inv, self.log, self.stop_event, self.session,
                            extra_urls=urls, threads=cfg.threads)
                        if set(js_urls) - set(res.js_files):
                            analysis = jsrecon.analyze_js(
                                set(js_urls) - set(res.js_files), self.inv, self.log,
                                self.stop_event, self.session, base_domain=cfg.target,
                                threads=max(5, cfg.threads // 3),
                                max_files=cfg.max_js_files)
                            res.js_files = sorted(set(res.js_files) | set(js_urls))
                            res.js_endpoints = sorted(set(res.js_endpoints)
                                                      | set(analysis["endpoints"]))
                            res.secrets += analysis["secrets"]
                            urls |= {e for e in analysis["endpoints"] if e.startswith("http")}

                    after = (len(hosts), len(urls), len(live))
                    self.log("info", f"  round {round_no}: hosts {before[0]}->{after[0]}, "
                                     f"URLs {before[1]}->{after[1]}, live {before[2]}->{after[2]}")
                    if after == before:
                        self.log("info", f"  converged after {round_no} rounds — "
                                         f"nothing new to find")
                        break

                res.subdomains = sorted(hosts)
                res.urls = sorted(urls)
                if "endpoints" in planned and not self.stop_event.is_set():
                    res.api_endpoints = jsrecon.verify_endpoints(
                        res.js_endpoints, live, self.log, self.stop_event, self.session,
                        threads=max(5, cfg.threads // 2))

            res.hosts = [hr.as_dict() for hr in sorted(live.values(), key=lambda h: h.host)]
            findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 5))

            # Triage always runs: the point of the scan is one reportable bug,
            # not a list. It re-verifies its pick and captures fresh evidence,
            # so it needs the live session before the scan tears down.
            if not self.stop_event.is_set():
                report = triage.build_report(findings, self.session, self.log,
                                             target=cfg.target)
                res.report = {
                    "kind": report["kind"],
                    "markdown": triage.render_markdown(report),
                    "considered": report.get("considered", 0),
                    "dropped": report.get("dropped", 0),
                }
                if report["kind"] == "report":
                    res.report.update({
                        "severity": report["severity"],
                        "justification": report["justification"],
                        "finding": report["finding"].as_dict(),
                    })
                    # Only ever a rewrite of a finding that already passed the
                    # evidence gate. If the rewrite fails its own checks, the
                    # verified template stands — the AI cannot create, promote
                    # or soften a finding, only phrase one.
                    if self.ai and cfg.ai_report:
                        self.log("stage", "▶ AI assist — writing the report")
                        host = report["finding"].host or cfg.target
                        written = self.ai.write_report(report, host)
                        if written:
                            res.report["markdown_template"] = res.report["markdown"]
                            res.report["markdown"] = written
                            res.report["ai_written"] = True
                elif report["kind"] == "evidence_needed":
                    res.report.update({
                        "missing": report["missing"],
                        "finding": report["finding"].as_dict(),
                    })

            res.findings = [f.as_dict() for f in findings]
            if self.ai:
                res.ai = self.ai.summary()

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
