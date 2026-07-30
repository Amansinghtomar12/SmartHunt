"""Recon stages driven by :class:`smarthunt.engine.Scanner`.

Every stage follows the same contract: it receives a ``log`` callable and a
:class:`threading.Event` used for cancellation, prefers an external tool when
one is installed, and always has a pure-Python fallback so results never
depend on setup.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    _HAVE_REQUESTS = False

from . import extra_tools, sources, wordlists
from .tools import ToolInventory, run

USER_AGENT = "SmartHunt/1.0 (+recon)"


# --------------------------------------------------------------------------- #
# Result containers
# --------------------------------------------------------------------------- #
@dataclass
class HostResult:
    """A single host and everything learned about it."""

    host: str
    ips: list[str] = field(default_factory=list)
    cname: str = ""
    ports: list[int] = field(default_factory=list)
    url: str = ""
    status: int | None = None
    title: str = ""
    server: str = ""
    content_length: int | None = None
    tech: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "host": self.host, "ips": self.ips, "cname": self.cname,
            "ports": sorted(self.ports), "url": self.url, "status": self.status,
            "title": self.title, "server": self.server,
            "content_length": self.content_length, "tech": self.tech,
        }


@dataclass
class Finding:
    """A potential issue worth a human's attention.

    The fields below ``source`` are what separates a scanner hit from something
    a triager can act on: which OWASP category it belongs to, the exact request
    that proved it, and what boundary it crossed.  Checks that cannot fill them
    leave them empty, and :mod:`smarthunt.triage` will refuse to report the
    finding rather than dress it up.
    """

    host: str
    name: str
    severity: str  # critical / high / medium / low / info
    detail: str = ""
    source: str = ""

    # --- reportability -----------------------------------------------------
    owasp: str = ""            # e.g. "A01:2021 Broken Access Control"
    endpoint: str = ""         # full URL the issue lives at
    method: str = ""           # HTTP method that triggered it
    param: str = ""            # parameter or body field, when relevant
    boundary: str = ""         # the security boundary that was crossed
    expected: str = ""         # what a correctly-behaving server would do
    actual: str = ""           # what this server actually did
    impact: str = ""           # demonstrated impact, in proven language only
    remediation: list = field(default_factory=list)
    evidence: object = None    # smarthunt.evidence.Evidence, when captured
    confidence: str = "low"    # low / medium / high — set by the checker

    def as_dict(self) -> dict:
        data = {"host": self.host, "name": self.name, "severity": self.severity,
                "detail": self.detail, "source": self.source}
        for key in ("owasp", "endpoint", "method", "param", "boundary",
                    "expected", "actual", "impact", "confidence"):
            value = getattr(self, key)
            if value:
                data[key] = value
        if self.remediation:
            data["remediation"] = list(self.remediation)
        if self.evidence is not None:
            data["evidence"] = self.evidence.as_dict()
        return data


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def make_session(retries: int = 1):
    """Build a resilient requests session (``None`` when requests is missing)."""
    if not _HAVE_REQUESTS:
        return None
    sess = requests.Session()
    retry = Retry(total=retries, backoff_factor=0.3, status_forcelist=[502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    return sess


# --------------------------------------------------------------------------- #
# Stage: subdomain enumeration  (wildcard mode)
# --------------------------------------------------------------------------- #
def enumerate_subdomains(domain, inv: ToolInventory, wordlist, log, stop,
                         threads=60, use_bruteforce=True) -> set[str]:
    """Discover subdomains via every installed tool plus all passive sources."""
    found: set[str] = {domain}

    # --- external passive tools (run them all, not just the first) --------
    for tool in ("subfinder", "assetfinder", "amass", "findomain", "chaos",
                 "github-subdomains", "shosubgo"):
        if stop.is_set() or not inv.has(tool):
            continue
        cmd = _subdomain_cmd(tool, domain)
        if not cmd:
            continue
        log("info", f"Running {tool}")
        code, out, err = run(cmd, timeout=300)
        if code in (0, 124) and out:
            new = {l.strip().lower().lstrip("*.") for l in out.splitlines() if l.strip()}
            new = {n for n in new if n.endswith(domain)}
            log("info", f"  {tool}: {len(new)} subdomains")
            found |= new
        elif code not in (0, 124):
            log("warn", f"  {tool} failed: {err.strip()[:120]}")

    # --- the wider arsenal (sublist3r, crobat, haktrails, cero, …) --------
    if not stop.is_set():
        found |= extra_tools.run_stage(
            extra_tools.S_SUBDOMAIN, {"domain": domain}, inv, log, stop)

    # --- passive OSINT sources (always run — pure Python) -----------------
    if not stop.is_set():
        log("info", "Querying passive sources (crt.sh, OTX, urlscan, wayback, ...)")
        found |= sources.gather_subdomains(domain, log, stop)

    # Anything guessed rather than attested has to survive the wildcard check.
    wildcard_ips = detect_wildcard(domain, log, stop)

    # --- DNS bruteforce ----------------------------------------------------
    if use_bruteforce and not stop.is_set():
        guessed = _bruteforce(domain, wordlist, inv, log, stop, threads)
        found |= _drop_wildcard_hits(guessed, wildcard_ips, log, stop, threads)

    # --- permutation of what we already have -------------------------------
    if not stop.is_set() and len(found) > 1:
        permuted = _permute(domain, found, inv, log, stop, threads)
        found |= _drop_wildcard_hits(permuted, wildcard_ips, log, stop, threads)

    return {h for h in found if h and (h == domain or h.endswith("." + domain))}


def _subdomain_cmd(tool, domain):
    return {
        "subfinder": ["subfinder", "-silent", "-all", "-d", domain],
        "assetfinder": ["assetfinder", "--subs-only", domain],
        "amass": ["amass", "enum", "-passive", "-d", domain, "-silent"],
        "findomain": ["findomain", "-t", domain, "-q"],
        "chaos": ["chaos", "-silent", "-d", domain],
        "github-subdomains": ["github-subdomains", "-d", domain],
        "shosubgo": ["shosubgo", "-d", domain],
    }.get(tool)


def _bruteforce(domain, wordlist, inv, log, stop, threads):
    """Bruteforce subdomain labels — via puredns/shuffledns if present, else sockets."""
    labels = wordlist or wordlists.SUBDOMAINS
    candidates = [f"{label}.{domain}" for label in labels]
    log("info", f"DNS bruteforce: {len(candidates)} candidates")

    tool = inv.first("puredns", "shuffledns", "massdns", "dnsx")
    if tool:
        log("info", f"  using {tool}")
        payload = "\n".join(candidates)
        cmd = {
            "puredns": ["puredns", "resolve", "--quiet"],
            "shuffledns": ["shuffledns", "-silent", "-d", domain],
            "massdns": ["massdns", "-r", "/etc/resolv.conf", "-t", "A", "-o", "S", "-q"],
            "dnsx": ["dnsx", "-silent", "-a"],
        }[tool]
        code, out, _ = run(cmd, timeout=300, input_text=payload)
        if code == 0:
            hits = {l.strip().split()[0].lower() for l in out.splitlines() if l.strip()}
            hits = {h for h in hits if h.endswith(domain)}
            log("info", f"  {tool}: {len(hits)} resolved")
            return hits

    found = set()

    def resolve(host):
        if stop.is_set():
            return None
        try:
            socket.getaddrinfo(host, None)
            return host
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for host in pool.map(resolve, candidates):
            if stop.is_set():
                break
            if host:
                found.add(host)
                log("found", f"subdomain: {host}")
    return found


def _permute(domain, known, inv, log, stop, threads):
    """Generate and resolve permutations of already-known subdomains."""
    # Each generator uses a different mutation strategy, so their outputs barely
    # overlap — run every one that is installed and resolve the union.
    payload = "\n".join(sorted(known))
    commands = {
        "gotator": ["gotator", "-sub", "-", "-perm", "-", "-depth", "1", "-silent"],
        "dnsgen": ["dnsgen", "-"],
        "altdns": ["altdns", "-i", "/dev/stdin", "-o", "/dev/stdout"],
    }
    generated: set[str] = set(extra_tools.run_stage(
        extra_tools.S_PERMUTE, {"domain": domain, "hosts": known}, inv, log, stop))
    for tool, cmd in commands.items():
        if stop.is_set() or not inv.has(tool):
            continue
        log("info", f"Permutation via {tool}")
        code, out, _ = run(cmd, timeout=180, input_text=payload)
        if code != 0 or not out:
            continue
        produced = {l.strip() for l in out.splitlines() if l.strip().endswith(domain)}
        log("info", f"  {tool}: {len(produced)} permutations")
        generated |= produced
    if not generated:
        return set()
    candidates = sorted(generated)[:20000]
    log("info", f"  {len(candidates)} unique permutations to resolve")

    found = set()

    def resolve(host):
        if stop.is_set():
            return None
        try:
            socket.getaddrinfo(host, None)
            return host
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for host in pool.map(resolve, candidates):
            if stop.is_set():
                break
            if host:
                found.add(host)
    log("info", f"  permutation: {len(found)} new hosts resolved")
    return found


# --------------------------------------------------------------------------- #
# Stage: DNS resolution + wildcard detection
# --------------------------------------------------------------------------- #
def detect_wildcard(domain, log, stop, samples: int = 4) -> set[str]:
    """Return the IPs a wildcard DNS record answers with, or an empty set.

    Plenty of domains answer *every* name — ``*.example.com`` resolving to one
    parking IP. Without this check, bruteforce and permutation "discover"
    thousands of hosts that do not exist, and exhaustive mode turns that into
    an unbounded supply of garbage. Query names nobody would ever register; if
    they answer, every address they return belongs to the wildcard.
    """
    wildcard_ips: set[str] = set()
    for i in range(samples):
        if stop.is_set():
            return set()
        probe = f"smarthunt-wildcard-probe-{i}-{abs(hash((domain, i))) % 10**8}.{domain}"
        try:
            wildcard_ips |= {info[4][0] for info in socket.getaddrinfo(probe, None)}
        except Exception:
            return set()   # a name that should not resolve did not: no wildcard
    if wildcard_ips:
        log("warn", f"Wildcard DNS on *.{domain} -> {', '.join(sorted(wildcard_ips))}; "
                    f"bruteforce and permutation hits matching it will be dropped")
    return wildcard_ips


def _drop_wildcard_hits(candidates, wildcard_ips, log, stop, threads=60) -> set[str]:
    """Remove hosts that only resolve to the wildcard address."""
    if not wildcard_ips or not candidates:
        return set(candidates)

    def check(host):
        if stop.is_set():
            return None
        try:
            ips = {info[4][0] for info in socket.getaddrinfo(host, None)}
        except Exception:
            return None
        # Resolves somewhere the wildcard does not -> a real, distinct host.
        return host if ips - wildcard_ips else None

    kept = set()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for host in pool.map(check, list(candidates)):
            if host:
                kept.add(host)
    dropped = len(candidates) - len(kept)
    if dropped:
        log("info", f"  dropped {dropped} wildcard-DNS false positives")
    return kept


def resolve_hosts(hosts, inv, log, stop, threads=60):
    """Resolve hosts to IPs and CNAMEs. Returns ``{host: (ips, cname)}``."""
    hosts = list(hosts)
    resolved: dict[str, tuple[list[str], str]] = {}

    if inv.has("dnsx") and len(hosts) > 50:
        log("info", f"Resolving {len(hosts)} hosts with dnsx")
        code, out, _ = run(["dnsx", "-silent", "-a", "-cname", "-json"],
                           timeout=300, input_text="\n".join(hosts))
        if code == 0 and out:
            for line in out.splitlines():
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                host = j.get("host", "")
                if host:
                    resolved[host] = (j.get("a", []) or [], (j.get("cname") or [""])[0])
            log("info", f"DNS: {len(resolved)}/{len(hosts)} resolve")
            return resolved

    def resolve(host):
        if stop.is_set():
            return host, ([], "")
        ips, cname = [], ""
        try:
            infos = socket.getaddrinfo(host, None)
            ips = sorted({info[4][0] for info in infos})
        except Exception:
            pass
        try:
            canonical = socket.gethostbyname_ex(host)[0]
            if canonical and canonical.rstrip(".") != host:
                cname = canonical.rstrip(".")
        except Exception:
            pass
        return host, (ips, cname)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for host, data in pool.map(resolve, hosts):
            if stop.is_set():
                break
            if data[0]:
                resolved[host] = data
    log("info", f"DNS: {len(resolved)}/{len(hosts)} hosts resolve")
    return resolved


# --------------------------------------------------------------------------- #
# Stage: HTTP probing
# --------------------------------------------------------------------------- #
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def probe_http(hosts, inv, log, stop, session, threads=40):
    """Probe hosts over https then http; keep the first that responds."""
    hosts = list(hosts)
    results: dict[str, HostResult] = {}

    # --- httpx (preferred) -------------------------------------------------
    if inv.has("httprobe") and not inv.has("httpx") and hosts and not stop.is_set():
        log("info", "HTTP probing via httprobe")
        code, out, _ = run(["httprobe", "-c", "40"], timeout=300,
                           input_text="\n".join(hosts))
        if code in (0, 124) and out:
            probed = [l.strip() for l in out.splitlines() if l.strip().startswith("http")]
            log("info", f"  httprobe: {len(probed)} live URLs")
            hosts = sorted({urlparse(u).netloc for u in probed}) or hosts

    if inv.has("httpx") and hosts:
        log("info", f"Probing {len(hosts)} hosts with httpx")
        code, out, _ = run(
            ["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect",
             "-web-server", "-content-length", "-follow-redirects", "-timeout", "8"],
            timeout=600, input_text="\n".join(hosts),
        )
        if code in (0, 124) and out:
            for line in out.splitlines():
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                host = j.get("input") or j.get("host") or ""
                host = host.replace("https://", "").replace("http://", "").split("/")[0]
                if not host:
                    continue
                results[host] = HostResult(
                    host=host, url=j.get("url", ""), status=j.get("status_code"),
                    title=j.get("title", "") or "", server=j.get("webserver", "") or "",
                    content_length=j.get("content_length"),
                    tech=j.get("tech", []) or [],
                )
            log("info", f"HTTP: {len(results)} live web hosts (httpx)")
            if results:
                return results

    if session is None:
        log("warn", "requests not installed — HTTP probe skipped")
        return results

    # --- built-in prober ---------------------------------------------------
    def probe(host):
        if stop.is_set():
            return None
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                resp = session.get(url, timeout=10, allow_redirects=True, verify=False)
            except Exception:
                continue
            title = ""
            m = _TITLE_RE.search(resp.text or "")
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
            return HostResult(
                host=host, url=resp.url, status=resp.status_code, title=title,
                server=resp.headers.get("Server", ""), content_length=len(resp.content),
            )
        return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(probe, h) for h in hosts]
        for fut in as_completed(futures):
            if stop.is_set():
                break
            res = fut.result()
            if res:
                results[res.host] = res
                log("found", f"live: {res.url} [{res.status}] {res.title}")
    log("info", f"HTTP: {len(results)} live web hosts")
    return results


# --------------------------------------------------------------------------- #
# Stage: port scanning
# --------------------------------------------------------------------------- #
def scan_ports(hosts, ports, inv, log, stop, threads=300):
    """Scan ports via naabu/nmap when installed, else a threaded connect scan."""
    hosts = list(hosts)
    port_list = ports or list(wordlists.COMMON_PORTS.keys())
    open_ports: dict[str, list[int]] = {}

    # Port scanners are interchangeable implementations of the same scan, so
    # the best available one runs rather than all three repeating the work.
    tool = inv.first("naabu", "masscan", "nmap")
    if tool and hosts:
        log("info", f"Port scanning {len(hosts)} hosts with {tool}")
        port_arg = ",".join(str(p) for p in port_list)
        if tool == "naabu":
            code, out, _ = run(["naabu", "-silent", "-p", port_arg, "-list", "-"],
                               timeout=600, input_text="\n".join(hosts))
            if code in (0, 124):
                for line in out.splitlines():
                    if ":" in line:
                        host, _, port = line.strip().rpartition(":")
                        try:
                            open_ports.setdefault(host, []).append(int(port))
                        except ValueError:
                            continue
                if open_ports:
                    log("info", f"naabu: open ports on {len(open_ports)} hosts")
                    return open_ports
        else:
            code, out, _ = run(["nmap", "-Pn", "-T4", "--open", "-p", port_arg,
                                "-oG", "-"] + hosts[:100], timeout=900)
            if code == 0:
                for line in out.splitlines():
                    m = re.match(r"Host: \S+ \(([^)]*)\).*Ports: (.*)", line)
                    if not m:
                        continue
                    host = m.group(1) or ""
                    for chunk in m.group(2).split(","):
                        parts = chunk.strip().split("/")
                        if len(parts) > 1 and parts[1] == "open":
                            open_ports.setdefault(host, []).append(int(parts[0]))
                if open_ports:
                    return open_ports

    targets = [(h, p) for h in hosts for p in port_list]
    log("info", f"Port scan: {len(hosts)} hosts x {len(port_list)} ports")

    def check(target):
        host, port = target
        if stop.is_set():
            return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                if s.connect_ex((host, port)) == 0:
                    return host, port
        except Exception:
            return None
        return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(check, t) for t in targets]
        for fut in as_completed(futures):
            if stop.is_set():
                break
            hit = fut.result()
            if hit:
                host, port = hit
                open_ports.setdefault(host, []).append(port)
                log("found", f"open port: {host}:{port} ({wordlists.COMMON_PORTS.get(port, '?')})")
    return open_ports


# --------------------------------------------------------------------------- #
# Stage: URL / endpoint collection (crawling + archives)
# --------------------------------------------------------------------------- #
def collect_urls(domain, live_results, inv, log, stop, session,
                 include_subs=True, crawl_depth=2, max_pages=300):
    """Collect URLs from archives, external crawlers, and the built-in crawler."""
    urls: set[str] = set()

    # --- archives (pure Python, always) ------------------------------------
    if not stop.is_set():
        log("info", "Collecting archived URLs (wayback, OTX, commoncrawl, urlscan)")
        urls |= sources.gather_urls(domain, log, stop, include_subs=include_subs)

    # --- external archive tools --------------------------------------------
    for tool in ("gau", "waybackurls", "urlfinder"):
        if stop.is_set() or not inv.has(tool):
            continue
        log("info", f"Running {tool}")
        cmd = {
            "gau": ["gau", "--threads", "5"] + (["--subs"] if include_subs else []) + [domain],
            "waybackurls": ["waybackurls", domain],
            "urlfinder": ["urlfinder", "-silent", "-d", domain],
        }[tool]
        code, out, _ = run(cmd, timeout=300, input_text=domain)
        if code in (0, 124) and out:
            new = {l.strip() for l in out.splitlines() if l.strip().startswith("http")}
            log("info", f"  {tool}: {len(new)} URLs")
            urls |= new

    # --- external crawlers --------------------------------------------------
    seeds = [r.url for r in live_results.values() if r.url] or [f"https://{domain}"]
    for tool in ("katana", "hakrawler", "gospider"):
        if stop.is_set() or not inv.has(tool):
            continue
        log("info", f"Crawling with {tool}")
        if tool == "katana":
            cmd = ["katana", "-silent", "-jc", "-kf", "all", "-d", str(crawl_depth), "-list", "-"]
            code, out, _ = run(cmd, timeout=420, input_text="\n".join(seeds))
        elif tool == "hakrawler":
            cmd = ["hakrawler", "-subs", "-u", "-d", str(crawl_depth)]
            code, out, _ = run(cmd, timeout=420, input_text="\n".join(seeds))
        else:
            cmd = ["gospider", "-q", "-d", str(crawl_depth), "-s", seeds[0]]
            code, out, _ = run(cmd, timeout=420)
        if code in (0, 124) and out:
            new = {l.strip() for l in out.splitlines() if l.strip().startswith("http")}
            log("info", f"  {tool}: {len(new)} URLs")
            urls |= new

    # --- built-in crawler ---------------------------------------------------
    if session is not None and not stop.is_set():
        urls |= _builtin_crawl(seeds, domain, log, stop, session, crawl_depth, max_pages)

    scoped = {u for u in urls if _in_scope(u, domain, include_subs)}
    log("info", f"URL collection: {len(scoped)} in-scope URLs ({len(urls)} total seen)")
    return scoped


def collect_extra_urls(domain, live_results, inv, log, stop) -> set[str]:
    """Archive and crawler tools beyond the built-in set."""
    ctx = {"domain": domain,
           "live_urls": [r.url for r in live_results.values() if r.url]}
    return {u for u in extra_tools.run_stage(extra_tools.S_URLS, ctx, inv, log, stop)
            if u.startswith("http")}


def _in_scope(url, domain, include_subs):
    try:
        host = urlparse(url).netloc.split("@")[-1].split(":")[0].lower()
    except Exception:
        return False
    if include_subs:
        return host == domain or host.endswith("." + domain)
    return host == domain


_HREF_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)


def _builtin_crawl(seeds, domain, log, stop, session, depth, max_pages):
    """Breadth-first same-scope crawler used when no external crawler exists."""
    seen: set[str] = set()
    found: set[str] = set()
    queue = [(s, 0) for s in seeds]
    log("info", f"Built-in crawl (depth {depth}, max {max_pages} pages)")

    while queue and len(seen) < max_pages and not stop.is_set():
        batch, queue = queue[:20], queue[20:]

        def fetch(item):
            url, lvl = item
            if url in seen or stop.is_set():
                return url, lvl, ""
            seen.add(url)
            try:
                resp = session.get(url, timeout=10, verify=False)
                ctype = resp.headers.get("Content-Type", "")
                if "html" not in ctype and "javascript" not in ctype:
                    return url, lvl, ""
                return resp.url, lvl, resp.text or ""
            except Exception:
                return url, lvl, ""

        with ThreadPoolExecutor(max_workers=10) as pool:
            for url, lvl, body in pool.map(fetch, batch):
                if not body:
                    continue
                found.add(url)
                if lvl >= depth:
                    continue
                for href in _HREF_RE.findall(body):
                    absolute = urljoin(url, href.strip())
                    if absolute.startswith("http") and _in_scope(absolute, domain, True):
                        found.add(absolute)
                        if absolute not in seen and len(seen) + len(queue) < max_pages:
                            queue.append((absolute, lvl + 1))
    log("info", f"  built-in crawl: {len(found)} URLs from {len(seen)} pages")
    return found


# --------------------------------------------------------------------------- #
# Stage: parameter discovery
# --------------------------------------------------------------------------- #
def build_fuzz_urls(urls, inv, log, stop, marker="FUZZ") -> list[str]:
    """Normalise parameterised URLs into one injection template per shape.

    qsreplace collapses ``?id=1``, ``?id=2``, ``?id=99`` into a single
    ``?id=FUZZ`` template, so the OWASP stage tests each distinct parameter
    shape once instead of hundreds of times with the same result.
    """
    param_urls = [u for u in urls if "?" in u and "=" in u]
    if not param_urls:
        return []
    if inv.has("qsreplace") and not stop.is_set():
        code, out, _ = run(["qsreplace", marker], timeout=120,
                           input_text="\n".join(param_urls[:20000]))
        if code == 0 and out:
            shaped = sorted({l.strip() for l in out.splitlines() if l.strip()})
            log("info", f"qsreplace: {len(param_urls)} URLs -> {len(shaped)} parameter shapes")
            return shaped
    # Built-in equivalent when qsreplace is not installed.
    shaped = set()
    for url in param_urls:
        parts = urlparse(url)
        keys = sorted(parse_qs(parts.query, keep_blank_values=True))
        if keys:
            shaped.add(urlunparse(parts._replace(
                query="&".join(f"{k}={marker}" for k in keys), fragment="")))
    return sorted(shaped)


def discover_params(domain, urls, inv, log, stop):
    """Extract parameter names from collected URLs and external param tools."""
    params: dict[str, set[str]] = {}
    interesting: set[str] = set()

    for url in urls:
        try:
            qs = parse_qs(urlparse(url).query)
        except Exception:
            continue
        if qs:
            interesting.add(url)
        for key, values in qs.items():
            params.setdefault(key, set()).update(v[:60] for v in values if v)

    # unfurl pulls parameter keys straight out of the collected URL corpus,
    # catching names that never appeared in a page we crawled.
    if inv.has("unfurl") and urls and not stop.is_set():
        log("info", "Running unfurl over the collected URLs")
        code, out, _ = run(["unfurl", "--unique", "keys"], timeout=120,
                           input_text="\n".join(list(urls)[:20000]))
        if code == 0 and out:
            new_keys = {l.strip() for l in out.splitlines() if l.strip()}
            log("info", f"  unfurl: {len(new_keys)} parameter names")
            for key in new_keys:
                params.setdefault(key, set())

    for tool in ("paramspider", "arjun"):
        if stop.is_set() or not inv.has(tool):
            continue
        log("info", f"Running {tool}")
        if tool == "paramspider":
            code, out, _ = run(["paramspider", "-d", domain], timeout=300)
        else:
            code, out, _ = run(["arjun", "-u", f"https://{domain}", "-oT", "/dev/stdout"], timeout=300)
        if code in (0, 124) and out:
            for line in out.splitlines():
                for key in re.findall(r"[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,30})=", line):
                    params.setdefault(key, set())
            log("info", f"  {tool}: parameter names collected")

    log("info", f"Parameters: {len(params)} unique names, {len(interesting)} parameterised URLs")
    return {
        "names": sorted(params),
        "values": {k: sorted(v)[:5] for k, v in params.items()},
        "urls": sorted(interesting),
    }


# --------------------------------------------------------------------------- #
# Stage: technology fingerprinting
# --------------------------------------------------------------------------- #
_HEADER_SIGNATURES = {
    "server": {"nginx": "Nginx", "apache": "Apache", "iis": "IIS", "cloudflare": "Cloudflare",
               "gunicorn": "Gunicorn", "openresty": "OpenResty", "litespeed": "LiteSpeed",
               "envoy": "Envoy", "caddy": "Caddy", "kestrel": "Kestrel"},
    "x-powered-by": {"php": "PHP", "asp.net": "ASP.NET", "express": "Express",
                     "next.js": "Next.js", "servlet": "Java Servlet"},
    "x-generator": {"drupal": "Drupal", "wordpress": "WordPress"},
    "x-amz-cf-id": {"": "CloudFront"},
    "x-shopify-stage": {"": "Shopify"},
}
_BODY_SIGNATURES = {
    "wp-content": "WordPress", "wp-includes": "WordPress", "/sites/default/files": "Drupal",
    "joomla": "Joomla", "csrf-token": "Laravel/Rails", "__next_data__": "Next.js",
    "ng-version": "Angular", "data-reactroot": "React", "window.__nuxt__": "Nuxt.js",
    "shopify": "Shopify", "x-magento": "Magento", "/_next/static": "Next.js",
    "jquery": "jQuery", "bootstrap": "Bootstrap", "vue.js": "Vue.js", "svelte": "Svelte",
    "cdn.shopify.com": "Shopify", "gtm.js": "Google Tag Manager", "graphql": "GraphQL",
}


def fingerprint(results, log, stop, session):
    """Attach detected technologies to each :class:`HostResult`, in place."""
    if session is None:
        return
    for host, res in results.items():
        if stop.is_set():
            break
        if res.tech:  # httpx already told us
            continue
        tech: set[str] = set()
        try:
            resp = session.get(res.url or f"https://{host}", timeout=10, verify=False)
        except Exception:
            continue
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for hname, mapping in _HEADER_SIGNATURES.items():
            if hname not in headers:
                continue
            value = headers[hname].lower()
            for needle, label in mapping.items():
                if needle in value:
                    tech.add(label)
        cookie = headers.get("set-cookie", "").lower()
        for needle, label in (("phpsessid", "PHP"), ("jsessionid", "Java"),
                              ("asp.net", "ASP.NET"), ("laravel_session", "Laravel"),
                              ("django", "Django"), ("_rails", "Ruby on Rails")):
            if needle in cookie:
                tech.add(label)
        body = (resp.text or "").lower()
        for needle, label in _BODY_SIGNATURES.items():
            if needle in body:
                tech.add(label)
        if tech:
            res.tech = sorted(tech)
            log("info", f"tech {host}: {', '.join(res.tech)}")


# --------------------------------------------------------------------------- #
# Stage: content discovery
# --------------------------------------------------------------------------- #
def discover_content(results, paths, inv, log, stop, session, threads=25, wordlist_path=""):
    """Probe interesting paths on each live host (ffuf/feroxbuster or built-in)."""
    hits: list[dict] = []
    path_list = paths or wordlists.CONTENT_PATHS

    installed_fuzzers = [t for t in ("ffuf", "feroxbuster", "dirsearch", "kiterunner")
                         if inv.has(t)]
    for tool in installed_fuzzers:
        if stop.is_set() or not (wordlist_path and results):
            break
        log("info", f"Content discovery via {tool}")
        for res in list(results.values())[:20]:
            if stop.is_set():
                break
            base = res.url.rstrip("/")
            cmd = {
                "ffuf": ["ffuf", "-s", "-w", wordlist_path, "-u", f"{base}/FUZZ",
                         "-mc", "200,201,204,301,302,401,403", "-t", "40"],
                "feroxbuster": ["feroxbuster", "-u", base, "-w", wordlist_path,
                                "-q", "--no-state"],
                "dirsearch": ["dirsearch", "-u", base, "-w", wordlist_path, "-q"],
                "kiterunner": ["kr", "scan", base, "-w", wordlist_path, "-q"],
            }[tool]
            code, out, _ = run(cmd, timeout=300)
            if code in (0, 124) and out:
                for line in out.splitlines():
                    line = line.strip()
                    if line:
                        hits.append({"url": line if line.startswith("http") else f"{base}/{line}",
                                     "status": 200, "length": 0, "type": "", "source": tool})
        log("info", f"  {tool}: {len(hits)} paths so far")

    # The built-in probe still runs after the external fuzzers. It carries real
    # status codes and content types (which the parsed tool output does not) and
    # covers the curated path list even when a tool used a different wordlist.
    if session is None:
        return hits

    targets = [(res.url.rstrip("/"), p) for res in results.values() for p in path_list]
    log("info", f"Content discovery: {len(results)} hosts x {len(path_list)} paths")

    def check(target):
        base, path = target
        if stop.is_set():
            return None
        url = f"{base}/{path}"
        try:
            resp = session.get(url, timeout=8, allow_redirects=False, verify=False)
        except Exception:
            return None
        if resp.status_code in (200, 201, 204, 301, 302, 401, 403):
            return {"url": url, "status": resp.status_code, "length": len(resp.content),
                    "type": resp.headers.get("Content-Type", "").split(";")[0]}
        return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(check, t) for t in targets]
        for fut in as_completed(futures):
            if stop.is_set():
                break
            hit = fut.result()
            if hit:
                hits.append(hit)
                log("found", f"path: {hit['url']} [{hit['status']}] ({hit['length']}b)")

    # Several fuzzers plus the built-in probe all feed this list, so the same
    # path can arrive more than once. Keep the richest entry per URL — the
    # built-in one carries a real status code and content type.
    best: dict[str, dict] = {}
    for hit in hits:
        current = best.get(hit["url"])
        if current is None or (not current.get("type") and hit.get("type")):
            best[hit["url"]] = hit
    return list(best.values())


# --------------------------------------------------------------------------- #
# Stage: subdomain takeover
# --------------------------------------------------------------------------- #
#: CNAME suffix -> (service, response fingerprint)
TAKEOVER_SIGNATURES = {
    "s3.amazonaws.com": ("AWS S3", "NoSuchBucket"),
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "herokuapp.com": ("Heroku", "No such app"),
    "herokudns.com": ("Heroku", "No such app"),
    "azurewebsites.net": ("Azure", "404 Web Site not found"),
    "cloudapp.azure.com": ("Azure", "404 Web Site not found"),
    "trafficmanager.net": ("Azure Traffic Manager", ""),
    "cloudfront.net": ("CloudFront", "ERROR: The request could not be satisfied"),
    "fastly.net": ("Fastly", "Fastly error: unknown domain"),
    "pantheonsite.io": ("Pantheon", "404 error unknown site"),
    "wpengine.com": ("WPEngine", "The site you were looking for couldn't be found"),
    "surge.sh": ("Surge", "project not found"),
    "bitbucket.io": ("Bitbucket", "Repository not found"),
    "ghost.io": ("Ghost", "Domain error"),
    "netlify.app": ("Netlify", "Not Found"),
    "readthedocs.io": ("ReadTheDocs", "unknown to Read the Docs"),
    "zendesk.com": ("Zendesk", "Help Center Closed"),
    "helpscoutdocs.com": ("HelpScout", "No settings were found for this company"),
    "statuspage.io": ("StatusPage", "You are being redirected"),
    "unbouncepages.com": ("Unbounce", "The requested URL was not found on this server"),
    "shopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    "tumblr.com": ("Tumblr", "Whatever you were looking for doesn't currently exist"),
    "wordpress.com": ("WordPress", "Do you want to register"),
    "desk.com": ("Desk", "Please try again or try Desk.com free"),
    "campaignmonitor.com": ("Campaign Monitor", "Trying to access your account?"),
    "acquia-sites.com": ("Acquia", "The site you are looking for could not be found"),
    "firebaseapp.com": ("Firebase", "Site Not Found"),
}


def check_takeover(resolved, results, inv, log, stop, session):
    """Detect dangling CNAMEs pointing at unclaimed third-party services."""
    findings: list[Finding] = []

    # subzy and subjack ship different fingerprint sets, so a service one of
    # them knows about the other may miss. Run both when both are installed.
    takeover_cmds = {
        "subzy": ["subzy", "run", "--targets", "-", "--hide_fails"],
        "subjack": ["subjack", "-w", "-", "-ssl"],
    }
    if resolved and not stop.is_set():
        hosts = "\n".join(resolved)
        for tool, cmd in takeover_cmds.items():
            if stop.is_set() or not inv.has(tool):
                continue
            log("info", f"Subdomain takeover check via {tool}")
            code, out, _ = run(cmd, timeout=300, input_text=hosts)
            if code in (0, 124) and out:
                for line in out.splitlines():
                    if "VULNERABLE" in line.upper():
                        findings.append(Finding(line.strip()[:80], "Subdomain takeover", "high",
                                                line.strip(), source=tool))

    # Built-in CNAME fingerprinting (always runs)
    for host, (ips, cname) in resolved.items():
        if stop.is_set():
            break
        if not cname:
            continue
        for suffix, (service, fingerprint_text) in TAKEOVER_SIGNATURES.items():
            if not cname.endswith(suffix):
                continue
            res = results.get(host)
            body = ""
            if session is not None:
                try:
                    resp = session.get(res.url if res and res.url else f"http://{host}",
                                       timeout=10, verify=False)
                    body = resp.text or ""
                except Exception:
                    body = ""
            if fingerprint_text and fingerprint_text.lower() in body.lower():
                findings.append(Finding(
                    host, f"Possible subdomain takeover ({service})", "high",
                    f"CNAME -> {cname}; response matches unclaimed-service fingerprint",
                    source="builtin"))
                log("found", f"TAKEOVER candidate: {host} -> {cname} ({service})")
            else:
                findings.append(Finding(
                    host, f"Third-party CNAME ({service})", "info",
                    f"CNAME -> {cname}; verify the resource is still claimed",
                    source="builtin"))
            break
    return findings


# --------------------------------------------------------------------------- #
# Stage: vulnerability / misconfiguration checks
# --------------------------------------------------------------------------- #
_SECURITY_HEADERS = ["Content-Security-Policy", "Strict-Transport-Security",
                     "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]

_SENSITIVE_PATHS = {
    ".env": ("Exposed .env file", "high"),
    ".git/config": ("Exposed .git repository", "high"),
    ".git/head": ("Exposed .git repository", "high"),
    "actuator/env": ("Spring Actuator env exposed", "high"),
    "actuator": ("Spring Actuator exposed", "medium"),
    "phpinfo": ("phpinfo() exposed", "medium"),
    "server-status": ("Apache server-status exposed", "medium"),
    ".htpasswd": ("Exposed .htpasswd", "high"),
    "backup": ("Possible backup file exposed", "medium"),
    "id_rsa": ("Possible SSH private key exposed", "critical"),
    ".ds_store": ("Exposed .DS_Store", "low"),
    "swagger": ("API documentation exposed", "info"),
    "graphql": ("GraphQL endpoint exposed", "info"),
    "adminer": ("Adminer database console exposed", "high"),
    "phpmyadmin": ("phpMyAdmin exposed", "medium"),
}


def check_vulns(results, content_hits, urls, inv, log, stop, session, nuclei_severity="low,medium,high,critical"):
    """Run nuclei/dalfox/crlfuzz when installed, plus always-on passive checks."""
    findings: list[Finding] = []

    # --- nuclei -------------------------------------------------------------
    if inv.has("nuclei") and results and not stop.is_set():
        target_urls = "\n".join(r.url for r in results.values() if r.url)
        log("info", f"Running nuclei against {len(results)} hosts")
        code, out, err = run(["nuclei", "-silent", "-jsonl", "-severity", nuclei_severity,
                              "-timeout", "8", "-rate-limit", "150"],
                             timeout=900, input_text=target_urls)
        if code in (0, 124) and out:
            count = 0
            for line in out.splitlines():
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                info = j.get("info", {})
                findings.append(Finding(
                    host=j.get("host", ""),
                    name=info.get("name", j.get("template-id", "nuclei")),
                    severity=info.get("severity", "info"),
                    detail=j.get("matched-at", ""),
                    source="nuclei",
                ))
                count += 1
            log("info", f"  nuclei: {count} findings")
        elif code not in (0, 124):
            log("warn", f"  nuclei failed: {err.strip()[:120]}")

    # --- dalfox (XSS on parameterised URLs) ---------------------------------
    param_urls = [u for u in urls if "?" in u][:200]
    if inv.has("dalfox") and param_urls and not stop.is_set():
        log("info", f"Running dalfox against {len(param_urls)} parameterised URLs")
        code, out, _ = run(["dalfox", "pipe", "--silence", "--no-color", "--skip-bav"],
                           timeout=600, input_text="\n".join(param_urls))
        if code in (0, 124) and out:
            for line in out.splitlines():
                if "[POC]" in line or "[VULN]" in line:
                    findings.append(Finding(_host_of(line), "XSS (dalfox)", "high",
                                            line.strip()[:300], source="dalfox"))

    # --- crlfuzz ------------------------------------------------------------
    if inv.has("crlfuzz") and param_urls and not stop.is_set():
        log("info", "Running crlfuzz")
        code, out, _ = run(["crlfuzz", "-s"], timeout=300, input_text="\n".join(param_urls[:100]))
        if code in (0, 124) and out:
            for line in out.splitlines():
                if line.strip().startswith("http"):
                    findings.append(Finding(_host_of(line), "CRLF injection", "medium",
                                            line.strip(), source="crlfuzz"))

    # --- corsy: CORS misconfiguration ---------------------------------------
    if inv.has("corsy") and results and not stop.is_set():
        log("info", "Running corsy")
        targets = "\n".join(r.url for r in results.values() if r.url)
        code, out, _ = run(["corsy", "-i", "-", "-q"], timeout=300, input_text=targets)
        if code in (0, 124) and out:
            for line in out.splitlines():
                if "http" in line and any(k in line.lower() for k in ("vulnerable", "misconfig")):
                    findings.append(Finding(_host_of(line), "CORS misconfiguration", "medium",
                                            line.strip()[:300], source="corsy"))

    # --- smuggler: request smuggling ----------------------------------------
    if inv.has("smuggler") and results and not stop.is_set():
        log("info", "Running smuggler")
        for res in list(results.values())[:15]:
            if stop.is_set():
                break
            code, out, _ = run(["smuggler", "-u", res.url], timeout=180)
            if code in (0, 124) and out and "POTENTIALLY VULNERABLE" in out.upper():
                findings.append(Finding(res.host, "HTTP request smuggling", "high",
                                        out.strip()[:300], source="smuggler"))

    if session is None:
        return findings

    # --- passive header / transport checks (always) -------------------------
    for host, res in results.items():
        if stop.is_set():
            break
        try:
            resp = session.get(res.url, timeout=10, verify=False)
        except Exception:
            continue
        headers = {k.lower(): v for k, v in resp.headers.items()}

        missing = [h for h in _SECURITY_HEADERS if h.lower() not in headers]
        if missing:
            findings.append(Finding(host, "Missing security headers", "low",
                                    ", ".join(missing), source="builtin"))
        if res.url.startswith("http://"):
            findings.append(Finding(host, "Primary endpoint served over plain HTTP", "low",
                                    "No transport encryption", source="builtin"))
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao == "*":
            findings.append(Finding(host, "Permissive CORS (ACAO: *)", "info", res.url, source="builtin"))
        if acao and acao != "*" and acac.lower() == "true":
            findings.append(Finding(host, "CORS reflects origin with credentials", "medium",
                                    f"ACAO: {acao}", source="builtin"))
        server = headers.get("server", "")
        if re.search(r"\d+\.\d+", server):
            findings.append(Finding(host, "Server version disclosed", "info", server, source="builtin"))
        for leaky in ("x-powered-by", "x-aspnet-version", "x-generator"):
            if leaky in headers:
                findings.append(Finding(host, f"Technology disclosed via {leaky}", "info",
                                        headers[leaky], source="builtin"))

    # --- escalate sensitive content hits ------------------------------------
    for hit in content_hits:
        if hit["status"] not in (200, 201):
            continue
        low = hit["url"].lower()
        for needle, (name, sev) in _SENSITIVE_PATHS.items():
            if needle in low:
                findings.append(Finding(urlparse(hit["url"]).netloc, name, sev,
                                        hit["url"], source="builtin"))
                break

    log("info", f"Vulnerability checks complete: {len(findings)} findings")
    return findings


def _host_of(text):
    m = re.search(r"https?://([^/\s\"']+)", text)
    return m.group(1) if m else ""


# --------------------------------------------------------------------------- #
# Stage: screenshots
# --------------------------------------------------------------------------- #
def screenshot(results, inv, log, stop, outdir):
    """Capture screenshots of live hosts via gowitness/aquatone when installed."""
    tool = inv.first("gowitness", "aquatone")
    if not tool or not results or stop.is_set():
        if not tool:
            log("info", "Screenshots skipped (install gowitness or aquatone)")
        return 0
    urls = "\n".join(r.url for r in results.values() if r.url)
    log("info", f"Capturing screenshots with {tool}")
    if tool == "gowitness":
        code, _, err = run(["gowitness", "scan", "file", "-f", "-", "--screenshot-path", outdir],
                           timeout=600, input_text=urls)
    else:
        code, _, err = run(["aquatone", "-out", outdir], timeout=600, input_text=urls)
    if code in (0, 124):
        log("info", f"  screenshots saved to {outdir}")
        return len(results)
    log("warn", f"  {tool} failed: {err.strip()[:120]}")
    return 0
