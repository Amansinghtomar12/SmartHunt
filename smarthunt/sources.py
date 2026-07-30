"""Free passive data sources queried directly over HTTP.

These are the pure-Python half of hybrid mode: even with zero external tools
installed, wildcard recon still pulls subdomains from certificate transparency
logs, threat-intel feeds and web archives, and domain mode still pulls historic
URLs from the archives.

Every source is best-effort — a failing or rate-limited source logs a warning
and the pipeline moves on.  Sources that need an API key are skipped unless the
matching environment variable is set.
"""

from __future__ import annotations

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore

USER_AGENT = "SmartHunt/1.0"
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-_.]*[a-z0-9])?$")


def _get(url, log, timeout=30, params=None, headers=None):
    """HTTP GET returning a response, or ``None`` on any failure."""
    if requests is None:
        return None
    try:
        hdrs = {"User-Agent": USER_AGENT}
        if headers:
            hdrs.update(headers)
        return requests.get(url, params=params, headers=hdrs, timeout=timeout, verify=True)
    except Exception as exc:
        log("warn", f"source request failed ({url.split('/')[2]}): {exc}")
        return None


def _clean(names, domain):
    """Normalise and keep only in-scope hostnames."""
    out = set()
    for raw in names:
        name = str(raw).strip().lower().lstrip("*.").rstrip(".")
        if not name or " " in name:
            continue
        if not (name == domain or name.endswith("." + domain)):
            continue
        if _DOMAIN_RE.match(name):
            out.add(name)
    return out


# --------------------------------------------------------------------------- #
# Subdomain sources
# --------------------------------------------------------------------------- #
def crtsh(domain, log):
    """Certificate transparency logs via crt.sh."""
    resp = _get("https://crt.sh/", log, params={"q": f"%.{domain}", "output": "json"}, timeout=45)
    if not resp or resp.status_code != 200 or not resp.text.strip():
        return set()
    try:
        data = resp.json()
    except Exception:
        return set()
    names = []
    for entry in data:
        names.extend(str(entry.get("name_value", "")).splitlines())
        names.append(str(entry.get("common_name", "")))
    return _clean(names, domain)


def certspotter(domain, log):
    """Cert transparency via SSLMate's CertSpotter."""
    resp = _get("https://api.certspotter.com/v1/issuances", log, params={
        "domain": domain, "include_subdomains": "true", "expand": "dns_names",
    })
    if not resp or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except Exception:
        return set()
    names = []
    for entry in data:
        names.extend(entry.get("dns_names", []))
    return _clean(names, domain)


def hackertarget(domain, log):
    """HackerTarget hostsearch API."""
    resp = _get("https://api.hackertarget.com/hostsearch/", log, params={"q": domain})
    if not resp or resp.status_code != 200 or "error" in resp.text.lower():
        return set()
    return _clean([line.split(",")[0] for line in resp.text.splitlines() if line], domain)


def alienvault(domain, log):
    """AlienVault OTX passive DNS."""
    resp = _get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", log)
    if not resp or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except Exception:
        return set()
    return _clean([r.get("hostname", "") for r in data.get("passive_dns", [])], domain)


def rapiddns(domain, log):
    """RapidDNS subdomain listing (HTML scrape)."""
    resp = _get(f"https://rapiddns.io/subdomain/{domain}", log, params={"full": "1"})
    if not resp or resp.status_code != 200:
        return set()
    names = re.findall(r"<td>([a-zA-Z0-9\-_.]+\.%s)</td>" % re.escape(domain), resp.text)
    return _clean(names, domain)


def anubis(domain, log):
    """JonLuca's Anubis subdomain database."""
    resp = _get(f"https://jonlu.ca/anubis/subdomains/{domain}", log)
    if not resp or resp.status_code != 200:
        return set()
    try:
        return _clean(resp.json(), domain)
    except Exception:
        return set()


def urlscan(domain, log):
    """urlscan.io search results."""
    resp = _get("https://urlscan.io/api/v1/search/", log, params={"q": f"domain:{domain}", "size": 1000})
    if not resp or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except Exception:
        return set()
    names = []
    for r in data.get("results", []):
        names.append(r.get("page", {}).get("domain", ""))
        names.append(r.get("task", {}).get("domain", ""))
    return _clean(names, domain)


def wayback_subs(domain, log):
    """Hostnames seen in the Wayback Machine's index."""
    resp = _get("https://web.archive.org/cdx/search/cdx", log, params={
        "url": f"*.{domain}/*", "output": "text", "fl": "original",
        "collapse": "urlkey", "limit": 20000,
    }, timeout=60)
    if not resp or resp.status_code != 200:
        return set()
    names = re.findall(r"https?://([a-zA-Z0-9\-_.]+)", resp.text)
    return _clean(names, domain)


def virustotal(domain, log):
    """VirusTotal subdomains (needs ``VT_API_KEY``)."""
    key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
    if not key:
        return set()
    resp = _get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains", log,
                params={"limit": 1000}, headers={"x-apikey": key})
    if not resp or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except Exception:
        return set()
    return _clean([d.get("id", "") for d in data.get("data", [])], domain)


def securitytrails(domain, log):
    """SecurityTrails subdomains (needs ``SECURITYTRAILS_API_KEY``)."""
    key = os.environ.get("SECURITYTRAILS_API_KEY") or os.environ.get("ST_API_KEY")
    if not key:
        return set()
    resp = _get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains", log,
                headers={"APIKEY": key})
    if not resp or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except Exception:
        return set()
    return _clean([f"{sub}.{domain}" for sub in data.get("subdomains", [])], domain)


def shodan_subs(domain, log):
    """Shodan DNS domain info (needs ``SHODAN_API_KEY``)."""
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return set()
    resp = _get(f"https://api.shodan.io/dns/domain/{domain}", log, params={"key": key})
    if not resp or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except Exception:
        return set()
    return _clean([f"{s}.{domain}" for s in data.get("subdomains", [])], domain)


#: All subdomain sources, ``(display name, callable)``.
SUBDOMAIN_SOURCES = [
    ("crt.sh", crtsh),
    ("certspotter", certspotter),
    ("hackertarget", hackertarget),
    ("alienvault-otx", alienvault),
    ("rapiddns", rapiddns),
    ("anubis", anubis),
    ("urlscan.io", urlscan),
    ("wayback", wayback_subs),
    ("virustotal", virustotal),
    ("securitytrails", securitytrails),
    ("shodan", shodan_subs),
]


def gather_subdomains(domain, log, stop, threads=8):
    """Query every passive source in parallel and merge the results."""
    found = set()
    if requests is None:
        log("warn", "requests not installed — passive sources unavailable")
        return found

    def query(item):
        name, fn = item
        if stop.is_set():
            return name, set()
        try:
            return name, fn(domain, log)
        except Exception as exc:
            log("warn", f"{name}: {exc}")
            return name, set()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(query, item) for item in SUBDOMAIN_SOURCES]
        for fut in as_completed(futures):
            if stop.is_set():
                break
            name, names = fut.result()
            if names:
                log("info", f"  {name}: {len(names)} subdomains")
                found |= names
    return found


# --------------------------------------------------------------------------- #
# Historic URL sources (used heavily by domain mode)
# --------------------------------------------------------------------------- #
def wayback_urls(domain, log, include_subs=True, limit=30000):
    """All URLs the Wayback Machine has indexed for a domain."""
    pattern = f"*.{domain}/*" if include_subs else f"{domain}/*"
    resp = _get("https://web.archive.org/cdx/search/cdx", log, params={
        "url": pattern, "output": "text", "fl": "original",
        "collapse": "urlkey", "limit": limit,
    }, timeout=90)
    if not resp or resp.status_code != 200:
        return set()
    return {u.strip() for u in resp.text.splitlines() if u.strip().startswith("http")}


def otx_urls(domain, log):
    """URLs recorded by AlienVault OTX."""
    resp = _get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list", log,
                params={"limit": 500, "page": 1})
    if not resp or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except Exception:
        return set()
    return {r.get("url", "") for r in data.get("url_list", []) if r.get("url")}


def commoncrawl_urls(domain, log, limit=10000):
    """URLs from the most recent Common Crawl index."""
    idx = _get("https://index.commoncrawl.org/collinfo.json", log)
    if not idx or idx.status_code != 200:
        return set()
    try:
        collections = idx.json()
        cdx_api = collections[0]["cdx-api"]
    except Exception:
        return set()
    resp = _get(cdx_api, log, params={
        "url": f"*.{domain}/*", "output": "json", "fl": "url", "limit": limit,
    }, timeout=90)
    if not resp or resp.status_code != 200:
        return set()
    urls = set()
    for line in resp.text.splitlines():
        try:
            urls.add(json.loads(line)["url"])
        except Exception:
            continue
    return urls


def urlscan_urls(domain, log):
    """URLs observed by urlscan.io."""
    resp = _get("https://urlscan.io/api/v1/search/", log,
                params={"q": f"domain:{domain}", "size": 1000})
    if not resp or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except Exception:
        return set()
    return {r.get("page", {}).get("url", "") for r in data.get("results", []) if r.get("page", {}).get("url")}


#: All archive URL sources, ``(display name, callable)``.
URL_SOURCES = [
    ("wayback", wayback_urls),
    ("alienvault-otx", otx_urls),
    ("commoncrawl", commoncrawl_urls),
    ("urlscan.io", urlscan_urls),
]


def gather_urls(domain, log, stop, include_subs=True, threads=4):
    """Query every archive source in parallel and merge the URL sets."""
    urls = set()
    if requests is None:
        return urls

    def query(item):
        name, fn = item
        if stop.is_set():
            return name, set()
        try:
            if fn is wayback_urls:
                return name, fn(domain, log, include_subs=include_subs)
            return name, fn(domain, log)
        except Exception as exc:
            log("warn", f"{name}: {exc}")
            return name, set()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(query, item) for item in URL_SOURCES]
        for fut in as_completed(futures):
            if stop.is_set():
                break
            name, found = fut.result()
            if found:
                log("info", f"  {name}: {len(found)} URLs")
                urls |= found
    return urls
