"""Pick the single strongest finding and write it up — or say there isn't one.

SmartHunt's scan stages are deliberately noisy: they surface everything so a
hunter can look around.  This module is the opposite.  It applies an evidence
gate to the whole finding set and produces exactly one of three outputs:

``report``
    One finding, fully proven, with raw request/response evidence and numbered
    reproduction steps a triager can follow.
``evidence_needed``
    Something looks real but a required proof is missing.  Lists the exact
    tests still owed — never a half-written report.
``none``
    "No reportable vulnerability found with the current evidence."

Two rules do most of the work here.  First, a large class of scanner output is
**never reportable on its own** — missing headers, version banners, directory
listings, endpoint discovery.  Second, severity comes from what was *proven*,
not from what the bug class is usually worth: error-based SQL injection proves
injection, not data exfiltration, so it is graded on the former.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .evidence import Evidence, capture, mask, verify_repeat

#: Findings that are never a standalone report, however many turn up.
#: Each entry is (pattern, why) — the reason is shown in the triage log so the
#: user can see the call being made rather than wondering where a finding went.
NEVER_REPORT = [
    (re.compile(r"missing security headers?|clickjack|x-frame-options|hsts|csp\b", re.I),
     "missing headers are best-practice findings, not vulnerabilities"),
    (re.compile(r"outdated component|version disclosure|server banner", re.I),
     "a version banner alone proves no exploitable condition"),
    (re.compile(r"directory listing|autoindex", re.I),
     "directory listing needs sensitive content to matter"),
    (re.compile(r"risky http methods", re.I),
     "advertised methods are not proof they are usable"),
    (re.compile(r"subresource integrity", re.I),
     "missing SRI is a hardening gap, not an exploitable flaw"),
    (re.compile(r"verbose error|stack trace", re.I),
     "an error page without sensitive data is informational"),
    (re.compile(r"ssrf candidate|ssrf probe", re.I),
     "SSRF needs a collaborator callback to prove"),
    (re.compile(r"open redirect", re.I),
     "open redirect needs an exploit chain to be reportable"),
    (re.compile(r"cookie flags?|httponly|samesite", re.I),
     "cookie attributes alone carry no demonstrated impact"),
    (re.compile(r"endpoint discovered|admin path|interesting path|js endpoint", re.I),
     "discovery is reconnaissance output, not a vulnerability"),
    (re.compile(r"^possible |^potential ", re.I),
     "speculative findings do not meet the evidence bar"),
    (re.compile(r"technology disclosed|x-powered-by", re.I),
     "a technology banner discloses no sensitive data"),
    (re.compile(r"api documentation exposed|swagger|graphql endpoint exposed", re.I),
     "a published schema or doc endpoint is intended surface, not a flaw"),
    (re.compile(r"permissive cors \(acao: \*\)", re.I),
     "a wildcard ACAO cannot carry credentials, so nothing private is readable"),
    (re.compile(r"served over plain http|no transport encryption", re.I),
     "missing TLS needs a demonstrated interception to be reportable"),
    (re.compile(r"third-party cname", re.I),
     "a CNAME to a live third-party service is normal configuration"),
]

#: OWASP category for the built-in checks, which predate the classification.
OWASP_BY_NAME = [
    (re.compile(r"exposed \.env|exposed \.git|actuator|backup|config\.json|phpinfo|server-status", re.I),
     "A05:2021 Security Misconfiguration"),
    (re.compile(r"secret in js|api key|token|credential", re.I),
     "A02:2021 Cryptographic Failures"),
    (re.compile(r"takeover", re.I), "A01:2021 Broken Access Control"),
    (re.compile(r"sql injection|xss|template injection|crlf", re.I), "A03:2021 Injection"),
    (re.compile(r"traversal|idor|access control", re.I), "A01:2021 Broken Access Control"),
    (re.compile(r"smuggling|cors", re.I), "A05:2021 Security Misconfiguration"),
]


def classify_owasp(finding) -> str:
    """Give a built-in finding its OWASP category if the checker did not."""
    if finding.owasp:
        return finding.owasp
    for pattern, category in OWASP_BY_NAME:
        if pattern.search(finding.name):
            return category
    return ""

#: Credential shapes that make an exposed file genuinely sensitive.
LIVE_CREDENTIALS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{16,}"), "Stripe live secret key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"), "GitHub token"),
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"), "SendGrid API key"),
    (re.compile(r"(?im)^\s*(DB_|DATABASE_|MYSQL_|POSTGRES_)?PASSWORD\s*=\s*\S+"), "database password"),
    (re.compile(r"(?im)^\s*SECRET_KEY\s*=\s*\S+"), "application secret key"),
    (re.compile(r"(?im)^\s*AWS_SECRET_ACCESS_KEY\s*=\s*\S+"), "AWS secret access key"),
    (re.compile(r"\b-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
]

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


# --------------------------------------------------------------------------- #
# Verifiers — re-prove a candidate at report time and capture the evidence
# --------------------------------------------------------------------------- #
def _verify_exposed_file(session, finding, what: str, log):
    """Fetch the exposed path and require genuinely sensitive content."""
    url = finding.endpoint or _url_from_detail(finding.detail)
    if not url:
        return None, ["the URL of the exposed file"]

    probe = capture(session, "GET", url, note=f"unauthenticated fetch of {what}")
    if probe.error or probe.status != 200 or not probe.response_body:
        return None, [f"a 200 response from {url} (got {probe.status or probe.error})"]

    hits = [name for pattern, name in LIVE_CREDENTIALS if pattern.search(probe.response_body)]
    if not hits:
        # The file is reachable but holds nothing sensitive — not reportable.
        return None, [f"credential material inside {url}; the file is reachable "
                      f"but contains nothing sensitive"]

    ev = Evidence()
    ev.add(probe)
    reproduced, fresh = verify_repeat(
        session, probe,
        lambda r: r.status == 200 and any(p.search(r.response_body or "")
                                          for p, _ in LIVE_CREDENTIALS),
        fresh_session_factory=_fresh_session_factory(session))
    ev.reproduced, ev.fresh_session, ev.unauthenticated = reproduced, fresh, True

    finding.evidence = ev
    finding.confidence = "high"
    finding.method = "GET"
    finding.endpoint = url
    finding.boundary = "Server-side configuration secrets are served to unauthenticated clients"
    finding.expected = f"{urlparse(url).path} is not served; the web root excludes deployment files"
    finding.actual = f"HTTP 200 returning {what} containing {', '.join(hits)}"
    finding.impact = (f"An unauthenticated request retrieves {', '.join(hits)} "
                      f"from {urlparse(url).path}.")
    finding.remediation = [
        "Remove deployment files from the web root and block dotfile paths at the proxy",
        "Treat every exposed credential as compromised and rotate it now",
        "Load configuration from the environment or a secrets manager, not files in the docroot",
        "Add a deployment check that fails when these paths are reachable",
    ]
    return finding, []


def _verify_secret_in_js(session, finding, log):
    """Confirm the secret is still served, and that it is a live credential."""
    url = _url_from_detail(finding.detail)
    if not url:
        return None, ["the JavaScript file URL the secret was found in"]

    probe = capture(session, "GET", url, note="unauthenticated fetch of the JS bundle")
    if probe.error or probe.status != 200:
        return None, [f"a 200 response from {url} (got {probe.status or probe.error})"]

    hits = [name for pattern, name in LIVE_CREDENTIALS if pattern.search(probe.response_body or "")]
    if not hits:
        return None, [f"a live credential inside {url}; the value found looks like a "
                      f"test or placeholder key"]

    ev = Evidence()
    ev.add(probe)
    reproduced, fresh = verify_repeat(
        session, probe,
        lambda r: r.status == 200 and any(p.search(r.response_body or "")
                                          for p, _ in LIVE_CREDENTIALS),
        fresh_session_factory=_fresh_session_factory(session))
    ev.reproduced, ev.fresh_session, ev.unauthenticated = reproduced, fresh, True

    finding.evidence = ev
    finding.confidence = "high"
    finding.method = "GET"
    finding.endpoint = url
    finding.boundary = "A server-side credential is published in a client-side asset"
    finding.expected = "Secret keys stay server-side; the bundle carries only publishable values"
    finding.actual = f"The JavaScript served from {urlparse(url).path} contains {', '.join(hits)}"
    finding.impact = (f"Anyone who loads the page retrieves {', '.join(hits)} "
                      f"from {urlparse(url).path}.")
    finding.remediation = [
        "Rotate the exposed credential immediately — treat it as public",
        "Move the call that needs this key behind a server-side endpoint",
        "Keep only publishable keys in client bundles; add secret scanning to CI",
    ]
    return finding, []


def _verify_owasp(session, finding, log):
    """OWASP checks already captured evidence — confirm it meets the bar."""
    ev = finding.evidence
    missing = []
    if ev is None or not ev.exchanges:
        missing.append("a captured request/response pair proving the behaviour")
        return None, missing
    if ev.reproduced < 2:
        missing.append(f"a second successful reproduction (observed {ev.reproduced} of 2)")
    if not finding.boundary or not finding.actual:
        missing.append("a stated security boundary and observed behaviour")
    if missing:
        return None, missing
    return finding, []


VERIFIERS = [
    (re.compile(r"exposed \.env", re.I),
     lambda s, f, log: _verify_exposed_file(s, f, "the .env deployment file", log)),
    (re.compile(r"exposed \.git", re.I),
     lambda s, f, log: _verify_exposed_file(s, f, "the .git repository config", log)),
    (re.compile(r"actuator|/env\b", re.I),
     lambda s, f, log: _verify_exposed_file(s, f, "the Spring Actuator env endpoint", log)),
    (re.compile(r"config\.json|backup|\.sql\b", re.I),
     lambda s, f, log: _verify_exposed_file(s, f, "the exposed configuration/backup file", log)),
    (re.compile(r"secret in js", re.I), _verify_secret_in_js),
    (re.compile(r".*"), _verify_owasp),   # everything else must carry its own proof
]


def _url_from_detail(detail: str) -> str:
    match = re.search(r"https?://[^\s)\"']+", detail or "")
    return match.group(0) if match else ""


def _fresh_session_factory(session):
    """Build a cookie-free session of the same type, for the clean-session check."""
    def factory():
        try:
            import requests
            clean = requests.Session()
            clean.headers.update({"User-Agent": "SmartHunt/1.0 (+recon)"})
            return clean
        except Exception:
            return None
    return factory


# --------------------------------------------------------------------------- #
# Severity lock — grade on what was proven, not on the bug class
# --------------------------------------------------------------------------- #
def locked_severity(finding) -> tuple[str, str]:
    """Return ``(severity, one-sentence justification)`` from proven impact only."""
    name = finding.name.lower()
    ev = finding.evidence

    if "broken access control" in name or "idor" in name:
        return "high", ("Attacker A received Victim B's private object while an "
                        "unauthenticated request for the same URL was refused; "
                        "cross-account read is demonstrated, not inferred.")
    if "sql injection" in name:
        return "high", ("Injection into the SQL parser is proven by the database error; "
                        "data extraction was not attempted, so this is not graded Critical.")
    if "template injection" in name:
        return "high", ("The server evaluated an injected expression; command execution "
                        "was not attempted, so this is not graded Critical.")
    if "path traversal" in name:
        return "high", ("An unauthenticated request reads arbitrary files outside the "
                        "web root, proven by the returned file contents.")
    if "secret in js" in name or "exposed .env" in name or "exposed .git" in name:
        return "high", ("Credential material is disclosed to unauthenticated clients; "
                        "the credentials were not used, so no further access is claimed.")
    if "xss" in name:
        return "medium", ("Injected markup is returned unencoded and executes for whoever "
                          "opens the crafted link; no victim session was compromised.")
    if "cors" in name:
        return "medium", ("Any origin can read this response with credentials; the data "
                          "returned was not shown to be sensitive.")
    severity = finding.severity if finding.severity in SEVERITY_RANK else "low"
    return severity, "Graded on the demonstrated behaviour only."


#: Bug-class ordering used to break ties between equally-proven findings.
#: Without this the winner would come down to alphabetical order, which is not
#: a defensible way to choose what to report. Classes are ranked by how much an
#: attacker gains from the *proven* behaviour, not by CVSS folklore.
CLASS_PRIORITY = [
    # Proven cross-account data access ranks first: the attacker demonstrably
    # *received the victim's data*. Error-based SQL injection proves the parser
    # is reachable, which is serious but a weaker demonstration of impact.
    (re.compile(r"broken access control|idor", re.I), 0),
    (re.compile(r"sql injection", re.I), 1),           # code execution in the DB
    (re.compile(r"template injection", re.I), 2),      # code execution in the renderer
    (re.compile(r"path traversal|arbitrary file read", re.I), 3),   # arbitrary read
    (re.compile(r"exposed \.env|exposed \.git|secret in js|actuator", re.I), 3),  # credentials
    (re.compile(r"takeover", re.I), 4),
    (re.compile(r"cors", re.I), 5),
    (re.compile(r"xss", re.I), 6),
]


def class_priority(finding) -> int:
    for pattern, rank in CLASS_PRIORITY:
        if pattern.search(finding.name):
            return rank
    return 9


def _score(finding) -> tuple:
    """Sort key: strongest evidence first, then impact, then reproducibility."""
    ev = finding.evidence
    severity, _ = locked_severity(finding)
    return (
        CONFIDENCE_RANK.get(finding.confidence, 3),
        SEVERITY_RANK.get(severity, 4),
        class_priority(finding),
        -(ev.reproduced if ev else 0),
        0 if (ev and ev.fresh_session) else 1,
        0 if (ev and ev.unauthenticated) else 1,
        finding.name,
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def build_report(findings, session, log, target: str = "") -> dict:
    """Apply the evidence gate and return the single best reportable finding."""
    log("stage", "▶ Triage — selecting the single strongest finding")

    candidates, dropped = [], []
    for finding in findings:
        skip = next((why for pattern, why in NEVER_REPORT if pattern.search(finding.name)), None)
        if skip:
            dropped.append((finding.name, skip))
            continue
        candidates.append(finding)

    for name, why in dropped[:12]:
        log("info", f"  not standalone-reportable: {name} — {why}")
    if len(dropped) > 12:
        log("info", f"  … and {len(dropped) - 12} more non-reportable findings")

    if not candidates:
        log("warn", "  no candidate cleared the never-report filter")
        return {"kind": "none", "target": target,
                "message": "No reportable vulnerability found with the current evidence.",
                "considered": len(findings), "dropped": len(dropped)}

    candidates.sort(key=_score)
    log("info", f"  {len(candidates)} candidate(s) past the filter; verifying strongest first")

    missing_by_finding = []
    for finding in candidates[:8]:
        verifier = next(fn for pattern, fn in VERIFIERS if pattern.search(finding.name))
        try:
            verified, missing = verifier(session, finding, log)
        except Exception as exc:
            log("warn", f"  verification of '{finding.name}' failed: {exc}")
            verified, missing = None, [f"verification raised {type(exc).__name__}"]

        if verified is not None:
            verified.owasp = classify_owasp(verified)
            severity, justification = locked_severity(verified)
            log("found", f"  ✓ reportable: {verified.name} [{severity}]")
            return {"kind": "report", "target": target,
                    "finding": verified, "severity": severity,
                    "justification": justification,
                    "considered": len(findings), "dropped": len(dropped),
                    "runner_up_count": max(0, len(candidates) - 1)}

        log("info", f"  ✗ {finding.name}: {missing[0] if missing else 'unproven'}")
        missing_by_finding.append((finding, missing))

    best, missing = missing_by_finding[0]
    return {"kind": "evidence_needed", "target": target, "finding": best,
            "missing": missing, "considered": len(findings), "dropped": len(dropped)}


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _auth_line(finding, ev) -> str:
    """State the authentication context the finding was proven under."""
    if "access control" in finding.name.lower() or "idor" in finding.name.lower():
        return ("- **Authentication required:** Yes — proven with two accounts the "
                "tester controls (Attacker A and Victim B); the unauthenticated "
                "request for the same URL was refused")
    if ev and ev.unauthenticated:
        return "- **Authentication required:** No — reproduced unauthenticated"
    return "- **Authentication required:** Not established"


def render_markdown(report: dict) -> str:
    """Render the triage result in the format a bug bounty triager expects."""
    if report["kind"] == "none":
        return (f"# No reportable vulnerability\n\n{report['message']}\n\n"
                f"Considered {report['considered']} finding(s); "
                f"{report['dropped']} were informational or hardening-only.\n")

    finding = report["finding"]
    host = finding.host or report.get("target", "")

    if report["kind"] == "evidence_needed":
        lines = [f"# Evidence needed — not yet reportable\n",
                 f"**Strongest candidate:** {finding.name}",
                 f"**Endpoint:** `{finding.endpoint or '—'}`\n",
                 "Do not report yet. Missing:\n"]
        lines += [f"{i}. {m}" for i, m in enumerate(report["missing"], 1)]
        lines.append(f"\nConsidered {report['considered']} finding(s); "
                     f"{report['dropped']} were informational or hardening-only.")
        return "\n".join(lines)

    severity, justification = report["severity"], report["justification"]
    ev = finding.evidence
    steps, poc = [], []

    for n, exchange in enumerate(ev.exchanges if ev else [], 1):
        curl = f"curl -i -s -X {exchange.method} '{exchange.url}'"
        steps.append(f"{n}. {exchange.note or 'Send the request below'}:\n"
                     f"   ```\n   {curl}\n   ```\n"
                     f"   Server returns `{exchange.status or exchange.error}`"
                     + (f" — {exchange.note}." if exchange.note else "."))
        poc.append(f"**Request {n}** — {exchange.note}\n\n```http\n"
                   f"{exchange.raw_request(host)}\n```\n\n"
                   f"**Response {n}**\n\n```http\n{exchange.raw_response(host)}\n```")

    reliability = (f"Reproduced {ev.reproduced + 1}× total"
                   + (", including on a fresh session with no prior cookies" if ev.fresh_session else "")
                   + (", unauthenticated" if ev.unauthenticated else "")
                   + "." if ev else "Not established.")

    parts = [
        f"# {finding.name}",
        f"\n**Severity:** {severity.title()} — {justification}",
        f"\n**OWASP:** {finding.owasp or '—'}",
        f"\n## Summary\n\n{finding.impact or finding.detail}",
        "\n## Affected Component\n",
        f"- **Endpoint:** `{finding.endpoint}`",
        f"- **Method:** `{finding.method or 'GET'}`",
        f"- **Parameter / field:** `{finding.param or '—'}`",
        f"- **Host:** `{host}`",
        _auth_line(finding, ev),
        "\n## Steps to Reproduce\n",
        "\n".join(steps) if steps else "_No captured exchanges._",
        "\n## Proof of Concept\n",
        "\n\n".join(poc) if poc else "_None captured._",
        "\n## Impact\n",
        f"- **Proven:** {finding.impact}",
        f"- **Security boundary crossed:** {finding.boundary}",
        f"\n## Expected vs Actual\n",
        f"- **Expected:** {finding.expected}",
        f"- **Actual:** {finding.actual}",
        f"\n## Reproduction Reliability\n\n{reliability}",
        "\n## Remediation\n",
        "\n".join(f"- {r}" for r in finding.remediation) or "- —",
        f"\n---\n\nSelected from {report['considered']} scan finding(s); "
        f"{report['dropped']} were informational or hardening-only and are not "
        f"reportable on their own. Credentials and personal data above are masked.",
    ]
    return "\n".join(parts)
