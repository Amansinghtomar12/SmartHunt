"""Raw HTTP evidence capture.

A finding is only reportable if a triager can reproduce it, so every active
check records the exact request it sent and the exact response it got back.
This module does the recording, the sanitising, and the repeat-verification.

Nothing here interprets a response — that is the checker's job.  This module
only answers "what precisely went over the wire, and does it happen again?"
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

MAX_BODY = 1400  # characters of body kept per exchange; enough to prove a point

#: ``(pattern, replacement)`` pairs applied to everything that reaches a report.
#: Replacements may use backreferences, which is what lets the credential-
#: assignment rules keep the *key* visible (it proves what the file holds) while
#: redacting the value. Order matters: specific token shapes run before the
#: generic key=value rule so they get their own descriptive placeholder.
_MASKS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), "JWT_TOKEN"),
    (re.compile(r"(?i)\bgh[pousr]_[A-Za-z0-9]{20,}"), "GITHUB_TOKEN"),
    (re.compile(r"(?i)\bsk_live_[A-Za-z0-9]{10,}"), "STRIPE_LIVE_KEY"),
    (re.compile(r"(?i)\bAKIA[0-9A-Z]{12,}"), "AWS_ACCESS_KEY"),
    (re.compile(r"(?i)\bSG\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}"), "SENDGRID_KEY"),
    (re.compile(r"(?i)\bAIza[A-Za-z0-9_-]{30,}"), "GOOGLE_API_KEY"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
                r"[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "PRIVATE_KEY"),
    # KEY=value / KEY: value in .env files, YAML, shell exports, query strings
    # and JSON. Deliberately not anchored to the start of a line: the same
    # assignment shows up mid-string inside a JSON body or a URL, and a redactor
    # that only covers the tidy .env case is not a redactor.
    (re.compile(r"""(?im)((?:^|[\s"',;(\[{&?])\s*(?:export\s+)?[A-Z0-9_]*"""
                r"(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE|CREDENTIAL)"
                r"""[A-Z0-9_]*\s*[=:]\s*)([^\s"',;)\]}&]+)"""), r"\1REDACTED_SECRET"),
    # "password": "value" in JSON/JS objects.
    (re.compile(r"""(?i)(["']?(?:password|passwd|secret|token|api_?key|private_?key)"""
                r"""["']?\s*:\s*)["']([^"']{3,})["']"""), r'\1"REDACTED_SECRET"'),
    (re.compile(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "TEST_EMAIL"),
]

#: Request headers whose values are replaced wholesale.
_SENSITIVE_HEADERS = {
    "cookie": "ATTACKER_SESSION",
    "set-cookie": "SESSION_COOKIE",
    "authorization": "ATTACKER_TOKEN",
    "x-api-key": "API_KEY",
    "x-csrf-token": "CSRF_TOKEN",
    "x-xsrf-token": "CSRF_TOKEN",
}


def mask(text: str) -> str:
    """Replace credentials and personal data with the report placeholders."""
    if not text:
        return ""
    for pattern, replacement in _MASKS:
        text = pattern.sub(replacement, text)
    return text


def mask_host(text: str, host: str) -> str:
    """Swap a real hostname for TARGET_HOST so reports can be shared safely."""
    return text.replace(host, "TARGET_HOST") if host else text


@dataclass
class Exchange:
    """One request/response pair, recorded verbatim."""

    method: str = "GET"
    url: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    status: int | None = None
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    elapsed_ms: int = 0
    note: str = ""          # what this exchange was meant to demonstrate
    error: str = ""

    def as_dict(self) -> dict:
        return asdict(self)

    def _credential_label(self) -> str:
        """Which account this exchange was sent as, for the placeholder.

        Access-control findings interleave two accounts, so labelling every
        cookie ATTACKER_SESSION would misrepresent which identity made which
        request — the one thing a triager reads these three requests to learn.
        """
        note = (self.note or "").lower()
        # Order matters: the attacker's note reads "Attacker A requests Victim
        # B's object", so a victim-first test would mislabel it.
        if note.startswith("attacker") or "attacker a requests" in note:
            return "ATTACKER_SESSION"
        if "victim" in note:
            return "VICTIM_SESSION"
        if "unauthenticated" in note or "anonymous" in note:
            return ""
        return "ATTACKER_SESSION"

    def raw_request(self, host: str = "") -> str:
        path = urlparse(self.url).path or "/"
        query = urlparse(self.url).query
        target = f"{path}?{query}" if query else path
        lines = [f"{self.method} {target} HTTP/1.1",
                 f"Host: {urlparse(self.url).netloc}"]
        session_label = self._credential_label()
        for key, value in self.request_headers.items():
            placeholder = _SENSITIVE_HEADERS.get(key.lower())
            if key.lower() == "cookie" and session_label:
                placeholder = session_label
            lines.append(f"{key}: {placeholder or value}")
        body = f"\n\n{self.request_body}" if self.request_body else ""
        return mask_host(mask("\n".join(lines) + body), host)

    def raw_response(self, host: str = "") -> str:
        if self.error:
            return f"(no response: {self.error})"
        lines = [f"HTTP/1.1 {self.status}"]
        for key, value in self.response_headers.items():
            placeholder = _SENSITIVE_HEADERS.get(key.lower())
            lines.append(f"{key}: {placeholder or value}")
        body = self.response_body[:MAX_BODY]
        if len(self.response_body) > MAX_BODY:
            body += f"\n… [{len(self.response_body) - MAX_BODY} more bytes]"
        return mask_host(mask("\n".join(lines) + ("\n\n" + body if body else "")), host)


@dataclass
class Evidence:
    """Everything needed to prove one finding, in the order a triager reads it."""

    exchanges: list[Exchange] = field(default_factory=list)
    reproduced: int = 0            # how many times the behaviour was re-observed
    fresh_session: bool = False    # confirmed on a brand-new connection/session
    unauthenticated: bool = False  # confirmed with no credentials at all

    def add(self, exchange: Exchange):
        self.exchanges.append(exchange)
        return exchange

    def as_dict(self) -> dict:
        return {
            "exchanges": [e.as_dict() for e in self.exchanges],
            "reproduced": self.reproduced,
            "fresh_session": self.fresh_session,
            "unauthenticated": self.unauthenticated,
        }

    @property
    def primary(self) -> Exchange | None:
        return self.exchanges[0] if self.exchanges else None


def capture(session, method: str, url: str, note: str = "", timeout: int = 10,
            headers: dict | None = None, data=None, allow_redirects: bool = False,
            params=None) -> Exchange:
    """Perform one request and record exactly what crossed the wire."""
    exchange = Exchange(method=method.upper(), url=url, note=note)
    sent = dict(headers or {})
    exchange.request_headers = sent
    if data is not None:
        exchange.request_body = data if isinstance(data, str) else str(data)

    if session is None:
        exchange.error = "requests is not installed"
        return exchange

    started = time.time()
    try:
        response = session.request(method.upper(), url, headers=sent or None, data=data,
                                   params=params, timeout=timeout, verify=False,
                                   allow_redirects=allow_redirects)
        exchange.elapsed_ms = int((time.time() - started) * 1000)
        exchange.status = response.status_code
        exchange.response_headers = dict(response.headers)
        # Record the request as the library actually built it, not as we asked.
        exchange.url = response.request.url or url
        exchange.request_headers = dict(response.request.headers)
        body = response.text or ""
        exchange.response_body = body[:MAX_BODY * 3]
    except Exception as exc:
        exchange.elapsed_ms = int((time.time() - started) * 1000)
        exchange.error = f"{type(exc).__name__}: {exc}"[:200]
    return exchange


def verify_repeat(session, exchange: Exchange, predicate, attempts: int = 2,
                  fresh_session_factory=None) -> tuple[int, bool]:
    """Re-run an exchange and count how many times ``predicate`` still holds.

    Returns ``(times_reproduced, held_on_a_fresh_session)``.  The skill's
    false-positive checks require both: a one-off response, or one that only
    reproduces on the warm session that first saw it, is not evidence.
    """
    reproduced = 0
    for _ in range(attempts):
        repeat = capture(session, exchange.method, exchange.url,
                         note="reproduction attempt",
                         headers={k: v for k, v in exchange.request_headers.items()
                                  if k.lower() not in ("content-length", "host")},
                         data=exchange.request_body or None)
        if predicate(repeat):
            reproduced += 1

    fresh_ok = False
    if fresh_session_factory is not None:
        clean = fresh_session_factory()
        if clean is not None:
            probe = capture(clean, exchange.method, exchange.url,
                            note="fresh session, no prior cookies")
            fresh_ok = predicate(probe)
            try:
                clean.close()
            except Exception:
                pass
    return reproduced, fresh_ok
