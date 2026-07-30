"""OWASP Top 10 (2021) active checks.

Every check is **non-destructive**: GET-style probes, bounded request counts, no
payload that writes, deletes, or degrades the target.  Checks read; they do not
change state.

Each check captures the exact request/response that triggered it and states its
own confidence honestly.  A check that cannot prove a boundary was crossed says
so — :mod:`smarthunt.triage` would rather report nothing than dress a scanner
hit up as a vulnerability.

Two categories deliberately cannot reach ``high`` confidence here:

``A10 SSRF``
    Proving SSRF needs a tester-controlled collaborator to observe the callback.
    Without ``--collaborator`` these are recorded as candidates needing evidence.
``A09 Logging failures``
    Not externally observable. Only verbose-error leakage is reported.
"""

from __future__ import annotations

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .evidence import Evidence, capture, verify_repeat
from .modules import Finding

MARKER = "sm4rthunt"

CATEGORIES = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
}

# --- high-precision response signatures ------------------------------------ #
SQL_ERRORS = [
    (re.compile(r"SQL syntax.*?MySQL|check the manual that corresponds to your (MySQL|MariaDB)", re.I), "MySQL"),
    (re.compile(r"PostgreSQL.*?ERROR|pg_query\(\)|unterminated quoted string at or near", re.I), "PostgreSQL"),
    (re.compile(r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string", re.I), "MSSQL"),
    (re.compile(r"SQLite3?::|sqlite3.OperationalError|SQLITE_ERROR", re.I), "SQLite"),
    (re.compile(r"ORA-\d{5}|Oracle error|quoted string not properly terminated", re.I), "Oracle"),
]

TRAVERSAL_SIGNATURES = [
    (re.compile(r"root:.?:0:0:"), "/etc/passwd contents"),
    (re.compile(r"\[(font|extension)s\]\r?\n", re.I), "win.ini contents"),
]

STACK_TRACES = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python traceback"),
    (re.compile(r"at [\w.$]+\((\w+\.java:\d+)\)"), "Java stack trace"),
    (re.compile(r"(Fatal error|Warning): .*? in .*? on line \d+", re.I), "PHP error"),
    (re.compile(r"System\.(NullReference|Argument)\w*Exception"), ".NET exception"),
    (re.compile(r"\bActiveRecord::|RAILS_ROOT|app/controllers/"), "Rails error"),
]

SERIALIZED_MARKERS = [
    (re.compile(r"^rO0AB"), "Java serialized object (base64)"),
    (re.compile(r"\bO:\d+:\"[A-Za-z_]"), "PHP serialized object"),
]

#: Parameter names that commonly take a URL — SSRF candidates.
SSRF_PARAMS = {"url", "uri", "target", "dest", "destination", "redirect", "redir",
               "next", "continue", "return", "return_to", "returnurl", "image",
               "image_url", "imageurl", "callback", "webhook", "fetch", "load",
               "src", "source", "domain", "host", "site", "proxy", "feed", "data"}

#: Parameter names worth injection testing.
INJECTABLE_HINTS = {"id", "user", "userid", "user_id", "account", "order", "q",
                    "query", "search", "s", "name", "email", "page", "file",
                    "path", "doc", "document", "cat", "category", "product",
                    "item", "key", "filter", "sort", "lang", "view", "template"}

#: Known-vulnerable version markers.  Deliberately small and conservative —
#: a version string alone is never reported as a standalone finding.
OUTDATED = [
    (re.compile(r"Apache/2\.4\.(4[0-9]|[0-3]?[0-9])\b"), "Apache httpd < 2.4.50", "CVE-2021-41773 family"),
    (re.compile(r"nginx/1\.(1[0-7]|[0-9])\.", re.I), "nginx < 1.18", "multiple advisories"),
    (re.compile(r"PHP/([45]\.|7\.[0-3])", re.I), "PHP < 7.4", "end of life"),
    (re.compile(r"OpenSSL/1\.0", re.I), "OpenSSL 1.0.x", "end of life"),
    (re.compile(r"jquery[/-]?1\.[0-9]\.", re.I), "jQuery 1.x", "known XSS sinks"),
]


def _mutate(url: str, param: str, value: str) -> str:
    """Return ``url`` with a single query parameter replaced."""
    parts = urlparse(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param] = [value]
    flat = urlencode({k: v[0] for k, v in query.items()}, safe="{}$/:")
    return urlunparse(parts._replace(query=flat))


def _params_of(url: str) -> list[str]:
    return list(parse_qs(urlparse(url).query, keep_blank_values=True))


def _is_html(exchange) -> bool:
    return "html" in (exchange.response_headers.get("Content-Type", "") or "").lower()


# --------------------------------------------------------------------------- #
# A03 — Injection
# --------------------------------------------------------------------------- #
def _check_sqli(session, url, param, baseline, log) -> Finding | None:
    """Error-based SQL injection: a quote provokes a database parser error."""
    probe = capture(session, "GET", _mutate(url, param, "'"),
                    note=f"single quote injected into '{param}'")
    if probe.error or not probe.response_body:
        return None
    for pattern, engine in SQL_ERRORS:
        if pattern.search(probe.response_body) and not pattern.search(baseline.response_body or ""):
            ev = Evidence()
            ev.add(baseline)
            ev.add(probe)
            reproduced, fresh = verify_repeat(
                session, probe,
                lambda r: bool(r.response_body and pattern.search(r.response_body)))
            ev.reproduced, ev.fresh_session, ev.unauthenticated = reproduced, fresh, True
            return Finding(
                host=urlparse(url).netloc, name=f"SQL injection ({engine}) in '{param}'",
                severity="critical", source="owasp", confidence="high", evidence=ev,
                owasp=CATEGORIES["A03"], endpoint=url, method="GET", param=param,
                detail=f"A single quote in '{param}' returns a {engine} parser error.",
                boundary="Untrusted input reaches the SQL query parser",
                expected=f"'{param}' is bound as a parameter; a quote is treated as data",
                actual=f"The {engine} parser receives the quote and errors, so the value is concatenated into the query",
                impact=f"Input to '{param}' is interpreted as SQL by the {engine} backend.",
                remediation=[
                    "Use parameterised queries / prepared statements for every value",
                    "Never build SQL by string concatenation with request data",
                    "Apply least-privilege database credentials",
                    "Return generic error pages; never expose database parser errors",
                ])
    return None


def _check_xss(session, url, param, baseline, log) -> Finding | None:
    """Reflected XSS: HTML metacharacters survive into an HTML response."""
    payload = f"'\"><svg/onload=alert({MARKER})>"
    probe = capture(session, "GET", _mutate(url, param, payload),
                    note=f"HTML metacharacters injected into '{param}'")
    if probe.error or not probe.response_body or not _is_html(probe):
        return None
    # Only a match where the angle brackets survived unencoded is meaningful.
    if f"<svg/onload=alert({MARKER})>" not in probe.response_body:
        return None
    ev = Evidence()
    ev.add(baseline)
    ev.add(probe)
    reproduced, fresh = verify_repeat(
        session, probe,
        lambda r: bool(r.response_body and f"<svg/onload=alert({MARKER})>" in r.response_body))
    ev.reproduced, ev.fresh_session, ev.unauthenticated = reproduced, fresh, True
    return Finding(
        host=urlparse(url).netloc, name=f"Reflected XSS in '{param}'",
        severity="medium", source="owasp", confidence="high", evidence=ev,
        owasp=CATEGORIES["A03"], endpoint=url, method="GET", param=param,
        detail=f"'{param}' is reflected into HTML with < > \" ' unencoded.",
        boundary="Untrusted input reaches the HTML parser as markup",
        expected=f"'{param}' is HTML-encoded before being written to the page",
        actual="The injected <svg onload=...> element is returned intact inside an HTML response",
        impact="A crafted link executes attacker-controlled JavaScript in the "
               "browser of whoever opens it, in this origin's context.",
        remediation=[
            "Contextually encode all untrusted output (HTML, attribute, JS, URL)",
            "Prefer templating that escapes by default; avoid raw interpolation",
            "Add a Content-Security-Policy that forbids inline script",
            "Set HttpOnly on session cookies to limit token theft",
        ])


def _check_ssti(session, url, param, baseline, log) -> Finding | None:
    """Server-side template injection: arithmetic gets evaluated server-side."""
    for payload, marker in (("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49")):
        probe = capture(session, "GET", _mutate(url, param, payload),
                        note=f"template expression injected into '{param}'")
        if probe.error or not probe.response_body:
            continue
        if marker in probe.response_body and payload not in probe.response_body \
                and marker not in (baseline.response_body or ""):
            ev = Evidence()
            ev.add(baseline)
            ev.add(probe)
            reproduced, fresh = verify_repeat(
                session, probe,
                lambda r: bool(r.response_body and marker in r.response_body
                               and payload not in r.response_body))
            ev.reproduced, ev.fresh_session, ev.unauthenticated = reproduced, fresh, True
            return Finding(
                host=urlparse(url).netloc, name=f"Server-side template injection in '{param}'",
                severity="critical", source="owasp", confidence="high", evidence=ev,
                owasp=CATEGORIES["A03"], endpoint=url, method="GET", param=param,
                detail=f"'{param}' containing {payload} returns {marker}.",
                boundary="Untrusted input is evaluated by the server-side template engine",
                expected=f"{payload} is rendered literally as text",
                actual=f"The server evaluated the expression and returned {marker}",
                impact="Input to this parameter is executed as a template expression "
                       "on the server.",
                remediation=[
                    "Never pass user input into template source; pass it as context data",
                    "Use a sandboxed/logic-less template engine where possible",
                    "Validate against an allow-list when a template must be selected by input",
                ])
    return None


def _check_traversal(session, url, param, baseline, log) -> Finding | None:
    """Path traversal: a file outside the web root is returned."""
    for payload in ("../../../../etc/passwd", "....//....//....//etc/passwd",
                    "..%2f..%2f..%2f..%2fetc%2fpasswd"):
        probe = capture(session, "GET", _mutate(url, param, payload),
                        note=f"traversal sequence injected into '{param}'")
        if probe.error or not probe.response_body:
            continue
        for pattern, what in TRAVERSAL_SIGNATURES:
            if pattern.search(probe.response_body):
                ev = Evidence()
                ev.add(baseline)
                ev.add(probe)
                reproduced, fresh = verify_repeat(
                    session, probe,
                    lambda r: bool(r.response_body and pattern.search(r.response_body)))
                ev.reproduced, ev.fresh_session, ev.unauthenticated = reproduced, fresh, True
                return Finding(
                    host=urlparse(url).netloc, name=f"Path traversal in '{param}'",
                    severity="high", source="owasp", confidence="high", evidence=ev,
                    owasp=CATEGORIES["A01"], endpoint=url, method="GET", param=param,
                    detail=f"'{param}' set to {payload} returns {what}.",
                    boundary="File access escapes the intended directory",
                    expected=f"'{param}' resolves only within the designated content directory",
                    actual=f"The response body contains {what}, a file outside the web root",
                    impact="An unauthenticated request reads arbitrary files from the "
                           "server filesystem.",
                    remediation=[
                        "Resolve the path and verify it stays within the base directory",
                        "Reference files by opaque ID mapped server-side, not by path",
                        "Reject any input containing path separators or dot segments",
                        "Run the service as a low-privilege user",
                    ])
    return None


# --------------------------------------------------------------------------- #
# A01 / A05 — access control and misconfiguration
# --------------------------------------------------------------------------- #
def _check_cors(session, url, log) -> Finding | None:
    """CORS: does the server reflect an arbitrary Origin *and* allow credentials?"""
    evil = "https://smarthunt-probe.invalid"
    probe = capture(session, "GET", url, note="arbitrary Origin header sent",
                    headers={"Origin": evil})
    if probe.error:
        return None
    acao = probe.response_headers.get("Access-Control-Allow-Origin", "")
    acac = probe.response_headers.get("Access-Control-Allow-Credentials", "")
    # Reflecting the origin with credentials is the exploitable shape. A bare
    # "*" cannot carry credentials, so it is not reportable on its own.
    if acao != evil or acac.lower() != "true":
        return None
    ev = Evidence()
    ev.add(probe)
    reproduced, fresh = verify_repeat(
        session, probe,
        lambda r: r.response_headers.get("Access-Control-Allow-Origin") == evil)
    ev.reproduced, ev.fresh_session = reproduced, fresh
    return Finding(
        host=urlparse(url).netloc, name="CORS reflects any origin with credentials",
        severity="high", source="owasp", confidence="high", evidence=ev,
        owasp=CATEGORIES["A05"], endpoint=url, method="GET",
        detail=f"Origin: {evil} is echoed back with Allow-Credentials: true.",
        boundary="Same-origin policy is waived for an arbitrary attacker origin",
        expected="Only origins on an allow-list are echoed, or credentials are not allowed",
        actual=f"Access-Control-Allow-Origin: {evil} with Access-Control-Allow-Credentials: true",
        impact="A page on any origin can read this endpoint's response using the "
               "victim's cookies.",
        remediation=[
            "Validate Origin against a server-side allow-list; never reflect it",
            "Do not combine Allow-Credentials: true with a dynamic origin",
            "Vary: Origin so caches do not serve one origin's response to another",
        ])


def _check_methods(session, url, log) -> Finding | None:
    """Dangerous HTTP methods left enabled."""
    probe = capture(session, "OPTIONS", url, note="OPTIONS to enumerate methods")
    allow = (probe.response_headers.get("Allow", "") or
             probe.response_headers.get("Access-Control-Allow-Methods", ""))
    risky = {m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")
             if m in allow.upper()}
    if not risky:
        return None
    ev = Evidence()
    ev.add(probe)
    return Finding(
        host=urlparse(url).netloc, name=f"Risky HTTP methods enabled: {', '.join(sorted(risky))}",
        severity="low", source="owasp", confidence="medium", evidence=ev,
        owasp=CATEGORIES["A05"], endpoint=url, method="OPTIONS",
        detail=f"Allow: {allow}",
        boundary="Write/diagnostic methods exposed to unauthenticated callers",
        expected="Only the methods the endpoint needs are advertised",
        actual=f"Server advertises {allow}",
        impact="", remediation=["Disable unused HTTP methods at the server or proxy"])


def _check_open_redirect(session, url, param, baseline, log) -> Finding | None:
    """Open redirect — only reported with a confirmed off-site 30x Location."""
    target = "https://smarthunt-probe.invalid/"
    probe = capture(session, "GET", _mutate(url, param, target),
                    note=f"external URL injected into '{param}'")
    if probe.error or probe.status not in (301, 302, 303, 307, 308):
        return None
    location = probe.response_headers.get("Location", "")
    if "smarthunt-probe.invalid" not in location:
        return None
    ev = Evidence()
    ev.add(probe)
    reproduced, fresh = verify_repeat(
        session, probe,
        lambda r: "smarthunt-probe.invalid" in (r.response_headers.get("Location", "") or ""))
    ev.reproduced, ev.fresh_session = reproduced, fresh
    return Finding(
        host=urlparse(url).netloc, name=f"Open redirect via '{param}'",
        severity="low", source="owasp", confidence="high", evidence=ev,
        owasp=CATEGORIES["A01"], endpoint=url, method="GET", param=param,
        detail=f"Location: {location}",
        boundary="Redirect target is attacker-controlled",
        expected=f"'{param}' accepts only relative paths or allow-listed hosts",
        actual=f"Server issues {probe.status} to {location}",
        impact="", remediation=[
            "Allow only relative paths, or match the host against an allow-list",
            "Map redirect targets to opaque server-side keys",
        ])


def _check_verbose_errors(session, url, log) -> Finding | None:
    """A09-adjacent: stack traces leaking internals."""
    probe = capture(session, "GET", url.rstrip("/") + f"/{MARKER}-nonexistent-'\"",
                    note="malformed path to provoke an error page")
    if probe.error or not probe.response_body:
        return None
    for pattern, what in STACK_TRACES:
        if pattern.search(probe.response_body):
            ev = Evidence()
            ev.add(probe)
            return Finding(
                host=urlparse(url).netloc, name=f"Verbose error page ({what})",
                severity="low", source="owasp", confidence="medium", evidence=ev,
                owasp=CATEGORIES["A09"], endpoint=probe.url, method="GET",
                detail=f"{what} returned to an unauthenticated request.",
                boundary="Internal implementation detail disclosed",
                expected="A generic error page", actual=f"{what} in the response body",
                impact="", remediation=[
                    "Disable debug mode in production",
                    "Return generic error pages; log details server-side only",
                ])
    return None


def _check_outdated(hosts, log) -> list[Finding]:
    """A06 — version banners matching known-outdated releases."""
    out = []
    for hr in hosts:
        banner = " ".join(filter(None, [hr.server, " ".join(hr.tech or [])]))
        for pattern, what, why in OUTDATED:
            if pattern.search(banner):
                ev = Evidence()   # banner only; no exchange proves exploitability
                out.append(Finding(
                    host=hr.host, name=f"Outdated component: {what}",
                    severity="low", source="owasp", confidence="low", evidence=ev,
                    owasp=CATEGORIES["A06"], endpoint=hr.url,
                    detail=f"{banner.strip()} — {why}",
                    boundary="", expected="", actual="", impact="",
                    remediation=["Upgrade to a currently supported release",
                                 "Suppress version banners in responses"]))
    return out


def _check_integrity(session, url, js_urls, log) -> list[Finding]:
    """A08 — third-party scripts without Subresource Integrity."""
    probe = capture(session, "GET", url, note="page fetched to inspect script tags")
    if probe.error or not probe.response_body or not _is_html(probe):
        return []
    host = urlparse(url).netloc
    out = []
    for match in re.finditer(r"<script[^>]+src=[\"']([^\"']+)[\"'][^>]*>", probe.response_body, re.I):
        tag, src = match.group(0), match.group(1)
        if not src.startswith("http"):
            continue
        if urlparse(src).netloc in ("", host):
            continue
        if "integrity=" in tag.lower():
            continue
        ev = Evidence()
        ev.add(probe)
        out.append(Finding(
            host=host, name="Third-party script without Subresource Integrity",
            severity="low", source="owasp", confidence="medium", evidence=ev,
            owasp=CATEGORIES["A08"], endpoint=url, detail=src,
            boundary="Third-party code executes with no integrity guarantee",
            expected="integrity= and crossorigin= on every external script",
            actual=f"<script src={src}> has no integrity attribute",
            impact="", remediation=[
                "Add Subresource Integrity hashes to external scripts",
                "Self-host critical third-party code where practical",
            ]))
        break  # one per host is plenty; this is never a standalone report
    return out


def _check_ssrf_candidates(session, url, param, collaborator, log) -> Finding | None:
    """A10 — needs a collaborator to prove; otherwise recorded as a candidate."""
    if not collaborator:
        ev = Evidence()
        return Finding(
            host=urlparse(url).netloc, name=f"SSRF candidate parameter '{param}'",
            severity="info", source="owasp", confidence="low", evidence=ev,
            owasp=CATEGORIES["A10"], endpoint=url, method="GET", param=param,
            detail=f"'{param}' takes a URL. Proving SSRF requires a collaborator "
                   f"host to observe the callback — re-run with --collaborator.",
            boundary="", expected="", actual="", impact="",
            remediation=["Allow-list outbound hosts; block link-local and private ranges"])

    probe = capture(session, "GET", _mutate(url, param, f"http://{collaborator}/{MARKER}"),
                    note=f"collaborator URL injected into '{param}'")
    ev = Evidence()
    ev.add(probe)
    return Finding(
        host=urlparse(url).netloc, name=f"SSRF probe sent via '{param}'",
        severity="info", source="owasp", confidence="low", evidence=ev,
        owasp=CATEGORIES["A10"], endpoint=url, method="GET", param=param,
        detail=f"Probe sent to http://{collaborator}/{MARKER}. Check the collaborator "
               f"for an inbound request from the target to confirm.",
        boundary="", expected="", actual="", impact="",
        remediation=["Allow-list outbound hosts; block link-local and private ranges"])


# --------------------------------------------------------------------------- #
# Stage entry point
# --------------------------------------------------------------------------- #
def run_checks(live, urls, endpoints, js_urls, log, stop: threading.Event, session,
               threads: int = 10, max_targets: int = 120,
               collaborator: str = "") -> list[Finding]:
    """Run the OWASP Top 10 suite over discovered URLs and endpoints."""
    findings: list[Finding] = []
    hosts = list(live.values())

    # Parameterised URLs are where injection lives; prefer them, then fill up
    # with plain endpoints for the per-host checks.
    param_urls, seen_shapes = [], set()
    for url in sorted(set(urls) | set(endpoints)):
        params = _params_of(url)
        if not params:
            continue
        shape = (urlparse(url).netloc, urlparse(url).path, tuple(sorted(params)))
        if shape in seen_shapes:
            continue
        seen_shapes.add(shape)
        param_urls.append(url)
    param_urls = param_urls[:max_targets]

    log("info", f"OWASP: {len(param_urls)} parameterised URLs, {len(hosts)} hosts")

    # --- per-parameter injection checks (A01/A03/A10) ----------------------
    jobs = []
    for url in param_urls:
        for param in _params_of(url):
            if param.lower() in SSRF_PARAMS:
                jobs.append((url, param, "ssrf"))
            if param.lower() in SSRF_PARAMS or "redirect" in param.lower():
                jobs.append((url, param, "redirect"))
            if param.lower() in INJECTABLE_HINTS or len(_params_of(url)) <= 4:
                jobs.extend([(url, param, "sqli"), (url, param, "xss"),
                             (url, param, "ssti"), (url, param, "traversal")])

    def run_one(job):
        url, param, kind = job
        if stop.is_set():
            return None
        baseline = capture(session, "GET", url, note="baseline, unmodified request")
        if baseline.error:
            return None
        try:
            if kind == "sqli":
                return _check_sqli(session, url, param, baseline, log)
            if kind == "xss":
                return _check_xss(session, url, param, baseline, log)
            if kind == "ssti":
                return _check_ssti(session, url, param, baseline, log)
            if kind == "traversal":
                return _check_traversal(session, url, param, baseline, log)
            if kind == "redirect":
                return _check_open_redirect(session, url, param, baseline, log)
            if kind == "ssrf":
                return _check_ssrf_candidates(session, url, param, collaborator, log)
        except Exception as exc:
            log("warn", f"  OWASP {kind} check failed on {param}: {exc}")
        return None

    if jobs:
        log("info", f"OWASP: {len(jobs)} injection probes across "
                    f"{len({(u, p) for u, p, _ in jobs})} parameters")
        with ThreadPoolExecutor(max_workers=threads) as pool:
            for future in as_completed([pool.submit(run_one, j) for j in jobs]):
                if stop.is_set():
                    break
                found = future.result()
                if found:
                    findings.append(found)
                    log("found", f"  [{found.severity}] {found.name} — {found.endpoint}")

    # --- per-host checks (A05/A06/A08/A09) ---------------------------------
    def per_host(hr):
        if stop.is_set() or not hr.url:
            return []
        out = []
        for check in (_check_cors, _check_methods, _check_verbose_errors):
            try:
                found = check(session, hr.url, log)
                if found:
                    out.append(found)
            except Exception:
                pass
        try:
            out += _check_integrity(session, hr.url, js_urls, log)
        except Exception:
            pass
        return out

    with ThreadPoolExecutor(max_workers=min(threads, 10)) as pool:
        for future in as_completed([pool.submit(per_host, h) for h in hosts[:60]]):
            if stop.is_set():
                break
            for found in future.result():
                findings.append(found)
                log("found", f"  [{found.severity}] {found.name} — {found.host}")

    findings += _check_outdated(hosts, log)

    by_category = {}
    for f in findings:
        by_category[f.owasp[:3]] = by_category.get(f.owasp[:3], 0) + 1
    if by_category:
        log("info", "OWASP coverage: " +
            ", ".join(f"{k}×{v}" for k, v in sorted(by_category.items())))
    return findings
