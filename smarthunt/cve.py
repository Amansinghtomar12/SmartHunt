"""Known-CVE matching against detected technologies and versions.

Two things are true at once, and the design has to respect both:

* Knowing the target runs Apache 2.4.49 is **useful intelligence** — it tells a
  hunter where to look next.
* A version banner is **not proof of anything**.  Banners lie, distributions
  backport fixes without bumping the version string, and the vulnerable code
  path may not even be reachable.

So everything this module produces is labelled inference, not evidence, and
carries ``confidence="low"``.  :mod:`smarthunt.triage` refuses to report a
CVE match on its own — a scanner that submits "you run Apache 2.4.49, here is
CVE-2021-41773" gets the report closed as invalid and the hunter's reputation
dinged.  What it does instead is tell you exactly what to test by hand, which
is what the intelligence is actually for.

Sources, in order of preference:

``BUILT_IN``
    A curated table of high-signal, remotely-checkable CVEs. Always available,
    no network needed.
``OSV.dev`` / ``NVD``
    Queried when ``--cve-online`` is set. Broader, slower, rate-limited.
"""

from __future__ import annotations

import json
import re
import threading
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .modules import Finding

CATEGORY = "A06:2021 Vulnerable and Outdated Components"

VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def _ver(text: str) -> tuple:
    """Parse the first dotted version in ``text`` into a comparable tuple."""
    match = VERSION_RE.search(text or "")
    if not match:
        return ()
    return tuple(int(p) for p in match.groups(default="0"))


@dataclass(frozen=True)
class KnownCVE:
    """One curated CVE with the version window it applies to."""

    product: str                 # regex matched against the banner / tech string
    cve: str
    severity: str                # our grading, not raw CVSS
    title: str
    min_version: tuple = ()      # inclusive; () means "any"
    max_version: tuple = ()      # exclusive; () means "any"
    verify: str = ""             # how a human confirms it, safely

    def applies(self, banner: str) -> bool:
        if not re.search(self.product, banner, re.I):
            return False
        version = _ver(banner)
        if not version:
            return not (self.min_version or self.max_version)
        if self.min_version and version < self.min_version:
            return False
        if self.max_version and version >= self.max_version:
            return False
        return True


#: Curated, remotely relevant CVEs. Deliberately small — every entry here is
#: one a hunter can actually go and check by hand within minutes.
BUILT_IN: tuple[KnownCVE, ...] = (
    KnownCVE(r"Apache(?:/| httpd )2\.4\.49", "CVE-2021-41773", "critical",
             "Apache path traversal / RCE (2.4.49)",
             verify="GET /cgi-bin/.%2e/%2e%2e/etc/passwd — a passwd body confirms it"),
    KnownCVE(r"Apache(?:/| httpd )2\.4\.50", "CVE-2021-42013", "critical",
             "Apache path traversal / RCE (2.4.50, incomplete 41773 fix)",
             verify="GET /cgi-bin/.%%32%65%%32%65/etc/passwd"),
    KnownCVE(r"nginx", "CVE-2019-20372", "medium",
             "nginx error_page request smuggling", max_version=(1, 17, 7),
             verify="requires an error_page redirect configuration; test manually"),
    KnownCVE(r"OpenSSL/1\.0\.1", "CVE-2014-0160", "critical",
             "Heartbleed — memory disclosure via TLS heartbeat",
             verify="testssl.sh --heartbleed, or nmap --script ssl-heartbleed"),
    KnownCVE(r"jquery", "CVE-2020-11022", "medium",
             "jQuery HTML manipulation XSS", min_version=(1, 2), max_version=(3, 5),
             verify="only exploitable where untrusted HTML reaches .html()/.append()"),
    KnownCVE(r"jquery", "CVE-2019-11358", "medium",
             "jQuery prototype pollution via $.extend", max_version=(3, 4),
             verify="check whether $.extend(true, {}, userInput) is reachable"),
    KnownCVE(r"bootstrap", "CVE-2018-14041", "medium",
             "Bootstrap XSS in data-target", max_version=(3, 4),
             verify="requires attacker-controlled data-* attributes"),
    KnownCVE(r"PHP/[45]\.|PHP/7\.[0-3]", "CVE-2019-11043", "high",
             "PHP-FPM underflow RCE (nginx + fastcgi_split_path_info)",
             verify="needs a specific nginx/PHP-FPM config; check the fastcgi rules"),
    KnownCVE(r"Tomcat", "CVE-2020-1938", "critical",
             "Ghostcat — AJP file read/inclusion", max_version=(9, 0, 31),
             verify="AJP connector on 8009 reachable? then file read is possible"),
    KnownCVE(r"Struts", "CVE-2017-5638", "critical",
             "Struts2 OGNL RCE via Content-Type",
             verify="malformed Content-Type header triggering an OGNL error"),
    KnownCVE(r"Confluence", "CVE-2022-26134", "critical",
             "Confluence OGNL injection RCE",
             verify="check the version against Atlassian's advisory"),
    KnownCVE(r"Spring", "CVE-2022-22965", "critical",
             "Spring4Shell — class loader RCE",
             verify="needs Spring MVC on Tomcat with JDK 9+; test data binding"),
    KnownCVE(r"Exchange", "CVE-2021-34473", "critical",
             "ProxyShell — Exchange pre-auth RCE",
             verify="check /autodiscover/autodiscover.json behaviour"),
    KnownCVE(r"Drupal", "CVE-2018-7600", "critical",
             "Drupalgeddon2 — form API RCE", max_version=(7, 59),
             verify="check the exact core version on the Drupal advisory"),
    KnownCVE(r"WordPress", "CVE-2022-21661", "high",
             "WordPress WP_Query SQL injection", max_version=(5, 8, 3),
             verify="requires a plugin passing user input into WP_Query"),
    KnownCVE(r"log4j|log4shell", "CVE-2021-44228", "critical",
             "Log4Shell — JNDI lookup RCE",
             verify="needs an out-of-band callback; use --collaborator"),
    KnownCVE(r"GitLab", "CVE-2021-22205", "critical",
             "GitLab ExifTool pre-auth RCE", max_version=(13, 10, 3),
             verify="check the GitLab version page against the advisory"),
    KnownCVE(r"Jenkins", "CVE-2024-23897", "critical",
             "Jenkins CLI arbitrary file read",
             verify="check whether the CLI endpoint is exposed"),
)


def _banners(hosts) -> dict:
    """Collect every version-bearing string per host."""
    per_host = {}
    for hr in hosts:
        parts = [hr.server or ""]
        parts += list(hr.tech or [])
        text = " ".join(p for p in parts if p).strip()
        if text:
            per_host[hr.host] = text
    return per_host


def _query_osv(package: str, version: str, timeout: int = 8) -> list[dict]:
    """Ask OSV.dev what it knows about a library version."""
    payload = json.dumps({"package": {"name": package}, "version": version}).encode()
    request = urllib.request.Request(
        "https://api.osv.dev/v1/query", data=payload,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return (json.loads(response.read().decode()) or {}).get("vulns", []) or []
    except Exception:
        return []


def _query_nvd(keyword: str, timeout: int = 12) -> list[dict]:
    """Keyword-search the NVD 2.0 API. Unauthenticated, so heavily rate-limited."""
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
           + urllib.parse.quote(keyword) + "&resultsPerPage=8")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = json.loads(response.read().decode())
    except Exception:
        return []
    out = []
    for item in (data.get("vulnerabilities") or [])[:8]:
        cve = item.get("cve", {})
        descriptions = cve.get("descriptions") or [{}]
        out.append({
            "id": cve.get("id", ""),
            "summary": (descriptions[0].get("value") or "")[:220],
        })
    return out


def check(hosts, js_files, log, stop: threading.Event, online: bool = False,
          max_online: int = 6) -> list[Finding]:
    """Match detected technology against known CVEs.

    Returns findings marked as *inference*: they name what to test, they do not
    claim the target is exploitable.
    """
    findings: list[Finding] = []
    per_host = _banners(hosts)
    if not per_host:
        log("info", "CVE check: nothing fingerprinted to match against")
        return findings

    log("info", f"CVE check: matching {len(per_host)} host banner(s) against "
                f"{len(BUILT_IN)} curated CVEs"
                + (" plus OSV/NVD online lookup" if online else ""))

    seen = set()
    for host, banner in per_host.items():
        if stop.is_set():
            break
        for known in BUILT_IN:
            if not known.applies(banner):
                continue
            key = (host, known.cve)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                host=host, name=f"Possible {known.cve}: {known.title}",
                severity=known.severity, source="cve", confidence="low",
                owasp=CATEGORY, endpoint="",
                detail=f"Banner '{banner[:90]}' matches the affected range. "
                       f"NOT verified — {known.verify or 'confirm manually'}.",
                boundary="", expected="", actual="",
                impact="",   # deliberately empty: nothing has been demonstrated
                remediation=[
                    f"Confirm the running version, then patch per the {known.cve} advisory",
                    "Suppress version banners so this is not trivially fingerprinted",
                ]))
            log("found", f"  [{known.severity}] {host}: {known.cve} — {known.title} "
                         f"(version-inferred, unverified)")

    if online and not stop.is_set():
        products = sorted({b.split()[0] for b in per_host.values() if b})[:max_online]
        for product in products:
            if stop.is_set():
                break
            for entry in _query_nvd(product):
                if not entry.get("id") or entry["id"] in {f.name.split(":")[0][9:]
                                                          for f in findings}:
                    continue
                log("info", f"  NVD: {entry['id']} mentions {product}")
    if not findings:
        log("info", "CVE check: no curated CVE matched the detected versions")
    return findings
