"""JavaScript gathering, endpoint extraction and secret hunting.

This is the heart of *domain mode*: given one host, collect every JavaScript
file it references (plus JS seen in archives), then mine those files for
endpoints, parameters and hardcoded credentials.

External tools (``subjs``, ``getJS``, ``jsluice``, ``mantra``, ``trufflehog``,
``LinkFinder``, ``SecretFinder``) are used when installed; the built-in regex
engine below always runs so results never depend on setup.
"""

from __future__ import annotations

import os
import re
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from .tools import ToolInventory, run

# --------------------------------------------------------------------------- #
# Endpoint extraction — the LinkFinder regex, plus path/URL patterns
# --------------------------------------------------------------------------- #
LINKFINDER_RE = re.compile(r"""
  (?:"|')                               # start quote
  (
    ((?:[a-zA-Z]{1,10}://|//)           # scheme or protocol-relative
      [^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})
    |
    ((?:/|\.\./|\./)                    # relative path
      [^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})
    |
    ([a-zA-Z0-9_\-/]{1,}/               # path with extension
      [a-zA-Z0-9_\-/]{1,}\.
      (?:[a-zA-Z]{1,4}|action)
      (?:[\?|#][^"|']{0,}|))
    |
    ([a-zA-Z0-9_\-/]{1,}/               # path without extension
      [a-zA-Z0-9_\-/]{3,}
      (?:[\?|#][^"|']{0,}|))
    |
    ([a-zA-Z0-9_\-]{1,}                 # filename with known extension
      \.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml|do|cgi|yaml|yml|env)
      (?:[\?|#][^"|']{0,}|))
  )
  (?:"|')                               # end quote
""", re.VERBOSE)

JS_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
JS_URL_IN_TEXT_RE = re.compile(r"""["'](https?://[^"']+\.js(?:\?[^"']*)?)["']""")

# Parameter names referenced inside JS (query keys, body fields, config keys)
PARAM_RE = re.compile(r"""[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,30})=""")

#: Secret patterns. ``(name, compiled regex, severity)``.
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("AWS Access Key ID", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), "critical"),
    ("AWS Secret Access Key", re.compile(r"""(?i)aws.{0,20}(?:secret|private).{0,20}["']([A-Za-z0-9/+=]{40})["']"""), "critical"),
    ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "high"),
    ("Google OAuth Client Secret", re.compile(r"\b(GOCSPX-[A-Za-z0-9\-_]{28})\b"), "critical"),
    ("Slack Token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,72})\b"), "critical"),
    ("Slack Webhook", re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,})"), "high"),
    ("GitHub Token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,})\b"), "critical"),
    ("GitLab Token", re.compile(r"\b(glpat-[A-Za-z0-9\-_]{20})\b"), "critical"),
    ("Stripe Live Key", re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"), "critical"),
    ("Stripe Publishable Key", re.compile(r"\b(pk_live_[0-9a-zA-Z]{24,})\b"), "low"),
    ("Twilio Account SID", re.compile(r"\b(AC[a-f0-9]{32})\b"), "medium"),
    ("SendGrid API Key", re.compile(r"\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b"), "critical"),
    ("Mailgun API Key", re.compile(r"\b(key-[0-9a-f]{32})\b"), "high"),
    ("Mailchimp API Key", re.compile(r"\b([0-9a-f]{32}-us[0-9]{1,2})\b"), "high"),
    ("Firebase URL", re.compile(r"(https://[a-z0-9\-]+\.firebaseio\.com)"), "medium"),
    ("Firebase API Key", re.compile(r"""(?i)apiKey["'\s:]{1,6}["'](AIza[0-9A-Za-z\-_]{35})["']"""), "high"),
    ("Heroku API Key", re.compile(r"""(?i)heroku.{0,20}["']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']"""), "high"),
    ("JWT", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"), "medium"),
    ("Private Key Block", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"), "critical"),
    ("Basic Auth in URL", re.compile(r"(https?://[a-zA-Z0-9_\-.]+:[^@\s/\"']{3,}@[a-zA-Z0-9_\-.]+)"), "high"),
    ("Generic API Key", re.compile(r"""(?i)(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|secret[_\-]?key)["'\s:=]{1,8}["']([A-Za-z0-9_\-]{20,64})["']"""), "medium"),
    ("Generic Password Assignment", re.compile(r"""(?i)(?:password|passwd|pwd)["'\s:=]{1,8}["']([^"'\s]{6,40})["']"""), "medium"),
    ("Cloudinary Credentials", re.compile(r"(cloudinary://[0-9]{10,}:[A-Za-z0-9_\-]+@[a-z0-9_\-]+)"), "high"),
    ("Algolia Admin Key", re.compile(r"""(?i)algolia.{0,20}(?:admin|api).{0,10}["']([a-f0-9]{32})["']"""), "high"),
    ("Internal Hostname", re.compile(r"(https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?[^\s\"']*)"), "low"),
    ("S3 Bucket URL", re.compile(r"(https?://[a-z0-9\-.]+\.s3[a-z0-9\-.]*\.amazonaws\.com)"), "low"),
]

# Values that look like secrets but are placeholders — suppressed to cut noise.
_FALSE_POSITIVE_RE = re.compile(
    r"(?i)^(?:your|my|the)?[_\-]?(?:api|secret|token|key|password|pass|xxx+|placeholder|example|sample|test|dummy|changeme|none|null|undefined|true|false)[_\-]?(?:key|here|value|token)?$"
)


def _is_placeholder(value: str) -> bool:
    if _FALSE_POSITIVE_RE.match(value.strip()):
        return True
    if re.fullmatch(r"[xX0*]{6,}", value):
        return True
    if value.count(".") > 4 and " " not in value:  # version strings / package paths
        return False
    return False


# --------------------------------------------------------------------------- #
# Step 1 — collect JavaScript file URLs
# --------------------------------------------------------------------------- #
def collect_js_urls(hosts_or_urls, inv: ToolInventory, log, stop: threading.Event,
                    session, extra_urls=None, threads: int = 20) -> set[str]:
    """Collect JavaScript file URLs from live hosts, archives and external tools."""
    js_urls: set[str] = set()
    targets = list(hosts_or_urls)

    # --- external: every installed collector, merged ------------------------
    # subjs and getJS find different files (one reads the response body, the
    # other follows the page), so running both is not redundant.
    if targets and not stop.is_set():
        if inv.has("subjs"):
            log("info", "JS discovery via subjs")
            code, out, _ = run(["subjs"], timeout=180, input_text="\n".join(targets))
            if code == 0:
                new = {l.strip() for l in out.splitlines() if l.strip().startswith("http")}
                log("info", f"  subjs: {len(new)} JS files")
                js_urls |= new
        if inv.has("getJS"):
            log("info", "JS discovery via getJS")
            for target in targets[:25]:
                if stop.is_set():
                    break
                url = target if target.startswith("http") else f"https://{target}"
                code, out, _ = run(["getJS", "--complete", "--url", url], timeout=90)
                if code == 0:
                    js_urls |= {l.strip() for l in out.splitlines()
                                if l.strip().startswith("http")}
            log("info", f"  getJS: {len(js_urls)} JS files so far")

    # --- built-in: parse each page for <script src> ------------------------
    if session is not None and not stop.is_set():
        def scrape(target):
            if stop.is_set():
                return set()
            url = target if target.startswith("http") else f"https://{target}"
            try:
                resp = session.get(url, timeout=12, verify=False)
            except Exception:
                return set()
            body = resp.text or ""
            out = set()
            for src in JS_SRC_RE.findall(body):
                out.add(urljoin(resp.url, src))
            for direct in JS_URL_IN_TEXT_RE.findall(body):
                out.add(direct)
            return out

        with ThreadPoolExecutor(max_workers=threads) as pool:
            for found in pool.map(scrape, targets):
                if stop.is_set():
                    break
                js_urls |= found

    # --- archives: any .js URL already collected elsewhere -----------------
    if extra_urls:
        archived = {u for u in extra_urls if urlparse(u).path.lower().endswith(".js")}
        if archived:
            log("info", f"  archives: {len(archived)} JS files")
            js_urls |= archived

    js_urls = {u for u in js_urls if u.startswith("http")}
    log("info", f"JS discovery: {len(js_urls)} unique JavaScript files")
    return js_urls


# --------------------------------------------------------------------------- #
# Step 2 — download and mine each JS file
# --------------------------------------------------------------------------- #
def analyze_js(js_urls, inv: ToolInventory, log, stop: threading.Event, session,
               base_domain: str = "", threads: int = 15, max_files: int = 400,
               max_bytes: int = 3_000_000) -> dict:
    """Download JS files and extract endpoints, parameters and secrets.

    Returns ``{"endpoints": [...], "params": [...], "secrets": [...], "files": int}``.
    """
    endpoints: set[str] = set()
    params: set[str] = set()
    secrets: list[dict] = []
    downloaded: dict[str, str] = {}

    if session is None:
        log("warn", "requests not installed — JS analysis skipped")
        return {"endpoints": [], "params": [], "secrets": [], "files": 0}

    urls = sorted(js_urls)[:max_files]
    if len(js_urls) > max_files:
        log("warn", f"JS analysis limited to first {max_files} of {len(js_urls)} files")
    log("info", f"Analyzing {len(urls)} JavaScript files")

    def fetch(url):
        if stop.is_set():
            return url, None
        try:
            resp = session.get(url, timeout=15, verify=False, stream=True)
            content = resp.raw.read(max_bytes, decode_content=True)
            return url, content.decode("utf-8", errors="ignore")
        except Exception:
            return url, None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(fetch, u): u for u in urls}
        for fut in as_completed(futures):
            if stop.is_set():
                break
            url, body = fut.result()
            if not body:
                continue
            downloaded[url] = body

            # endpoints
            for match in LINKFINDER_RE.finditer(body):
                candidate = match.group(1).strip()
                if 3 < len(candidate) < 300:
                    endpoints.add(candidate)
            # parameters
            params.update(PARAM_RE.findall(body))
            # secrets
            for name, pattern, severity in SECRET_PATTERNS:
                for hit in pattern.findall(body):
                    value = hit if isinstance(hit, str) else hit[0]
                    if not value or _is_placeholder(value):
                        continue
                    secrets.append({
                        "type": name,
                        "severity": severity,
                        "value": value[:80],
                        "source": url,
                    })

    # --- external enrichment: jsluice / mantra / trufflehog ----------------
    if downloaded and not stop.is_set():
        _run_external_js_tools(downloaded, inv, endpoints, secrets, log, stop)

    # Keep endpoints that look useful and, when possible, in scope
    cleaned = _filter_endpoints(endpoints, base_domain)
    deduped = _dedupe_secrets(secrets)

    log("info", f"JS analysis: {len(cleaned)} endpoints, {len(params)} params, "
                f"{len(deduped)} potential secrets across {len(downloaded)} files")
    return {
        "endpoints": sorted(cleaned),
        "params": sorted(params),
        "secrets": deduped,
        "files": len(downloaded),
    }


def _run_external_js_tools(downloaded, inv, endpoints, secrets, log, stop_flag=None):
    """Feed downloaded JS through jsluice / mantra / trufflehog when installed."""
    analysers = ("jsluice", "mantra", "trufflehog", "linkfinder", "secretfinder",
                 "xnLinkFinder", "gitleaks")
    if not any(inv.has(t) for t in analysers):
        return
    tmpdir = tempfile.mkdtemp(prefix="smarthunt-js-")
    paths = []
    for idx, (url, body) in enumerate(downloaded.items()):
        path = os.path.join(tmpdir, f"file{idx}.js")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
            paths.append((path, url))
        except Exception:
            continue

    if inv.has("jsluice") and paths:
        log("info", "Running jsluice over downloaded JS")
        code, out, _ = run(["jsluice", "urls"] + [p for p, _ in paths], timeout=180)
        if code == 0:
            import json as _json
            for line in out.splitlines():
                try:
                    endpoints.add(_json.loads(line).get("url", ""))
                except Exception:
                    continue
        code, out, _ = run(["jsluice", "secrets"] + [p for p, _ in paths], timeout=180)
        if code == 0:
            import json as _json
            for line in out.splitlines():
                try:
                    j = _json.loads(line)
                    secrets.append({
                        "type": f"jsluice:{j.get('kind', 'secret')}",
                        "severity": j.get("severity", "medium"),
                        "value": str(j.get("data", ""))[:80],
                        "source": j.get("filename", ""),
                    })
                except Exception:
                    continue

    # LinkFinder and xnLinkFinder pull endpoints regex-first; SecretFinder and
    # mantra hunt credentials. Each finds things the others miss, so run all
    # that are installed rather than stopping at the first.
    if inv.has("linkfinder") and paths:
        log("info", "Running LinkFinder over downloaded JS")
        for path, url in paths[:120]:
            if stop_flag and stop_flag.is_set():
                break
            code, out, _ = run(["linkfinder", "-i", path, "-o", "cli"], timeout=60)
            if code == 0:
                for line in out.splitlines():
                    hit = line.strip()
                    if hit and not hit.startswith("["):
                        endpoints.add(hit)

    if inv.has("xnLinkFinder") and paths:
        log("info", "Running xnLinkFinder over downloaded JS")
        code, out, _ = run(["xnLinkFinder", "-i", tmpdir, "-o", "cli"], timeout=240)
        if code == 0:
            for line in out.splitlines():
                hit = line.strip()
                if hit and not hit.startswith("["):
                    endpoints.add(hit)

    if inv.has("secretfinder") and paths:
        log("info", "Running SecretFinder over downloaded JS")
        for path, url in paths[:120]:
            if stop_flag and stop_flag.is_set():
                break
            code, out, _ = run(["secretfinder", "-i", path, "-o", "cli"], timeout=60)
            if code == 0:
                for line in out.splitlines():
                    if "->" in line:
                        kind, _, value = line.partition("->")
                        secrets.append({
                            "type": f"secretfinder:{kind.strip()[:40]}",
                            "severity": "high", "value": value.strip()[:80],
                            "source": url})

    if inv.has("mantra") and paths:
        log("info", "Running mantra over downloaded JS")
        code, out, _ = run(["mantra"], timeout=180,
                           input_text="\n".join(u for _, u in paths))
        if code == 0:
            for line in out.splitlines():
                if line.strip().startswith("[+]"):
                    secrets.append({"type": "mantra:secret", "severity": "high",
                                    "value": line.strip()[:80], "source": ""})

    if inv.has("gitleaks") and paths:
        log("info", "Running gitleaks over downloaded JS")
        code, out, _ = run(["gitleaks", "detect", "--source", tmpdir, "--no-git",
                            "--report-format", "json", "--report-path", "/dev/stdout"],
                           timeout=180)
        if out:
            import json as _json
            try:
                for item in _json.loads(out):
                    secrets.append({
                        "type": f"gitleaks:{item.get('RuleID', '?')}",
                        "severity": "high",
                        "value": str(item.get("Secret", ""))[:80],
                        "source": item.get("File", "")})
            except Exception:
                pass

    if inv.has("trufflehog"):
        log("info", "Running trufflehog over downloaded JS")
        code, out, _ = run(["trufflehog", "filesystem", tmpdir, "--json", "--no-update"], timeout=240)
        if code in (0, 183):
            import json as _json
            for line in out.splitlines():
                try:
                    j = _json.loads(line)
                    secrets.append({
                        "type": f"trufflehog:{j.get('DetectorName', '?')}",
                        "severity": "critical" if j.get("Verified") else "high",
                        "value": str(j.get("Raw", ""))[:80],
                        "source": j.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                    })
                except Exception:
                    continue


def _filter_endpoints(endpoints, base_domain):
    """Drop obvious junk (mime types, versions, css selectors) from endpoints."""
    out = set()
    junk = re.compile(r"^(?:image/|text/|application/|font/|video/|audio/|charset|utf-8|[0-9.]+)$", re.I)
    for ep in endpoints:
        ep = ep.strip().strip("\"'")
        if not ep or junk.match(ep):
            continue
        if len(ep) < 4 or len(ep) > 300:
            continue
        if ep.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:")):
            continue
        # Keep absolute in-scope URLs, and all relative paths
        if ep.startswith("http"):
            host = urlparse(ep).netloc.lower()
            if base_domain and not (host == base_domain or host.endswith("." + base_domain)):
                continue
        out.add(ep)
    return out


def _dedupe_secrets(secrets):
    """Collapse duplicate (type, value) pairs, keeping the first source."""
    seen = set()
    out = []
    for s in secrets:
        key = (s["type"], s["value"])
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda s: severity_rank.get(s["severity"], 5))
    return out


# --------------------------------------------------------------------------- #
# Step 3 — turn mined paths into confirmed, live API endpoints
# --------------------------------------------------------------------------- #
def verify_endpoints(endpoints, live, log, stop: threading.Event, session,
                     threads: int = 20, max_checks: int = 1500) -> list[dict]:
    """Probe every JS-derived path against every live host and keep what answers.

    Reading a bundle gives you *strings* — ``/api/v2/billing/invoices`` is a
    guess until something answers it.  In wildcard mode the same path often
    exists on some subdomains and not others (staging exposes what production
    hides), so each path is tried against each host rather than against the
    apex alone.  What comes back is the real, callable attack surface.
    """
    if session is None or not endpoints or not live:
        return []

    paths, absolute = set(), set()
    for endpoint in endpoints:
        if endpoint.startswith("http"):
            absolute.add(endpoint)
        elif endpoint.startswith("/") and len(endpoint) > 1:
            paths.add(endpoint.split("#")[0])

    bases = [hr.url or f"https://{hr.host}" for hr in live.values() if (hr.url or hr.host)]
    candidates = list(absolute)
    for base in bases:
        for path in paths:
            candidates.append(urljoin(base.rstrip("/") + "/", path.lstrip("/")))

    # Deduplicate while preserving a stable order, then bound the work.
    seen, ordered = set(), []
    for url in candidates:
        if url not in seen:
            seen.add(url)
            ordered.append(url)
    if len(ordered) > max_checks:
        log("warn", f"Endpoint verification capped at {max_checks} of {len(ordered)} candidates")
        ordered = ordered[:max_checks]

    log("info", f"Verifying {len(ordered)} candidate endpoints across {len(bases)} host(s)")

    def probe(url):
        if stop.is_set():
            return None
        try:
            resp = session.get(url, timeout=10, verify=False, allow_redirects=False)
        except Exception:
            return None
        if resp.status_code in (404, 400) or resp.status_code >= 500:
            return None
        ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip()
        body = resp.text or ""
        structured = ctype in ("application/json", "application/xml", "text/xml",
                               "application/graphql", "application/hal+json")
        looks_api = structured or "/api" in urlparse(url).path.lower() or \
            body.strip()[:1] in ("{", "[")
        return {
            "url": url,
            "status": resp.status_code,
            "type": ctype,
            "length": len(resp.content or b""),
            "api": bool(looks_api),
            "host": urlparse(url).netloc,
            "methods": "",
        }

    confirmed = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for result in pool.map(probe, ordered):
            if stop.is_set():
                break
            if result:
                confirmed.append(result)

    # For the API-shaped hits, ask which methods are allowed — that is what
    # turns "this path exists" into "this path accepts writes".
    api_hits = [c for c in confirmed if c["api"]][:120]

    def methods_of(hit):
        if stop.is_set():
            return
        try:
            resp = session.options(hit["url"], timeout=8, verify=False)
            allow = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods") or ""
            hit["methods"] = allow.strip()
        except Exception:
            pass

    if api_hits:
        with ThreadPoolExecutor(max_workers=min(threads, 10)) as pool:
            list(pool.map(methods_of, api_hits))

    confirmed.sort(key=lambda c: (not c["api"], c["url"]))
    log("info", f"✓ {len(confirmed)} endpoints answered "
                f"({sum(1 for c in confirmed if c['api'])} look like real APIs)")
    for hit in confirmed[:15]:
        if hit["api"]:
            extra = f"  [{hit['methods']}]" if hit["methods"] else ""
            log("found", f"  API {hit['status']} {hit['url']}{extra}")
    return confirmed
