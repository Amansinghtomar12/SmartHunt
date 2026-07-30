"""Authenticated scanning: session profiles, parsing and liveness checks.

Unauthenticated scanning only ever sees the front door.  The interesting half of
most applications — the account pages, the object IDs, the admin surface — is
behind a login, and a scanner that cannot hold a session simply never reaches
it.  This module lets the user hand SmartHunt a session they already have.

Two profiles are supported, and the second one is the point:

``attacker`` (Account A)
    Used for all authenticated crawling, discovery and testing.
``victim`` (Account B)
    Optional.  When present, SmartHunt can prove **broken access control** —
    Attacker A requesting Victim B's object and being served it.  That is the
    OWASP A01 proof standard, and it is impossible to demonstrate with one
    session.

Both profiles must be accounts the tester controls.  SmartHunt never touches
real users' data, and the access-control checks only ever read objects that
Account B has itself confirmed it owns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

#: Response markers that almost always mean "you are not logged in".
LOGGED_OUT_MARKERS = [
    re.compile(r"<title>[^<]*(sign in|log ?in|authenticate)[^<]*</title>", re.I),
    re.compile(r"\b(please|you must) (sign|log) ?in\b", re.I),
    re.compile(r'name=["\']password["\']', re.I),
    re.compile(r'"(error|message)"\s*:\s*"(unauthori[sz]ed|not authenticated|invalid token)"', re.I),
]

#: Headers a user might paste that we must not forward verbatim.
_SKIP_HEADERS = {"content-length", "host", "connection", "accept-encoding",
                 "transfer-encoding", ":authority", ":method", ":path", ":scheme"}


@dataclass
class SessionProfile:
    """One set of credentials, however the user chose to express them."""

    label: str = "attacker"
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    user_agent: str = ""
    #: A URL that requires authentication, used to prove the session is live.
    check_url: str = ""
    #: Text that appears only when logged in (a username, "Sign out", …).
    check_marker: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.cookies or self.headers)

    def describe(self) -> str:
        bits = []
        if self.cookies:
            bits.append(f"{len(self.cookies)} cookie(s)")
        if self.headers:
            bits.append(f"{len(self.headers)} header(s)")
        return f"{self.label}: {', '.join(bits) or 'not configured'}"

    def apply_to(self, session):
        """Stamp this profile onto a requests session."""
        if session is None:
            return session
        for name, value in self.cookies.items():
            session.cookies.set(name, value)
        session.headers.update(self.headers)
        if self.user_agent:
            session.headers["User-Agent"] = self.user_agent
        return session


def parse_cookie_string(raw: str) -> dict:
    """Parse a ``Cookie:`` header value — what devtools' "copy as cURL" gives."""
    cookies = {}
    for chunk in (raw or "").split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name, _, value = chunk.partition("=")
        name = name.strip()
        if name.lower() == "cookie":
            continue
        cookies[name] = value.strip()
    return cookies


def parse_header_block(raw: str) -> tuple[dict, dict]:
    """Parse a pasted raw header block into ``(headers, cookies)``.

    Accepts what a hunter actually has to hand: a block copied out of Burp or
    the browser's network tab, one ``Name: value`` per line.  A request line
    (``GET /x HTTP/1.1``) is ignored, and ``Cookie:`` is split out so the jar
    handles it rather than a static header.
    """
    headers, cookies = {}, {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+", line, re.I):
            continue          # a request line, not a header
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name, value = name.strip(), value.strip()
        if not name or not value or name.lower() in _SKIP_HEADERS:
            continue
        if name.lower() == "cookie":
            cookies.update(parse_cookie_string(value))
        else:
            headers[name] = value
    return headers, cookies


def build_profile(label: str, raw_headers: str = "", raw_cookies: str = "",
                  bearer: str = "", check_url: str = "",
                  check_marker: str = "") -> SessionProfile:
    """Build a profile from any combination of the input forms the UI offers."""
    headers, cookies = parse_header_block(raw_headers)
    cookies.update(parse_cookie_string(raw_cookies))
    if bearer:
        token = bearer.strip()
        if not token.lower().startswith(("bearer ", "basic ", "token ")):
            token = f"Bearer {token}"
        headers["Authorization"] = token
    return SessionProfile(label=label, cookies=cookies, headers=headers,
                          check_url=check_url.strip(),
                          check_marker=check_marker.strip())


def make_authenticated_session(profile: SessionProfile, base_session_factory):
    """A fresh session carrying ``profile``'s credentials."""
    session = base_session_factory()
    return profile.apply_to(session)


def verify(profile: SessionProfile, session, log) -> tuple[bool, str]:
    """Check the session is actually authenticated before the scan leans on it.

    A dead cookie does not fail loudly — the app just serves the login page with
    HTTP 200, and every subsequent finding is quietly about that login page. So
    this is checked once, up front, and the result is stated either way.
    """
    if not profile.configured:
        return False, "no credentials supplied"
    if not profile.check_url:
        return True, ("credentials loaded but unverified — set a check URL to "
                      "confirm the session is live")
    if session is None:
        return False, "requests is not installed"

    try:
        response = session.get(profile.check_url, timeout=12, verify=False,
                               allow_redirects=False)
    except Exception as exc:
        return False, f"check request failed: {type(exc).__name__}"

    if response.status_code in (301, 302, 303, 307, 308):
        location = response.headers.get("Location", "")
        if re.search(r"log ?in|sign ?in|auth", location, re.I):
            return False, f"redirected to {location[:70]} — session is not logged in"
    if response.status_code in (401, 403):
        return False, f"check URL returned {response.status_code} — session rejected"

    body = response.text or ""
    if profile.check_marker:
        if profile.check_marker in body:
            return True, f"verified — marker found at {urlparse(profile.check_url).path}"
        return False, (f"marker {profile.check_marker!r} absent from the check "
                       f"response — session is probably expired")

    for pattern in LOGGED_OUT_MARKERS:
        if pattern.search(body):
            return False, "check response looks like a login page — session is not live"
    return True, f"verified — {response.status_code} at {urlparse(profile.check_url).path}"


def summarise(attacker: SessionProfile, victim: SessionProfile) -> str:
    """One line for the log describing what authenticated testing is possible."""
    if not attacker.configured:
        return "Unauthenticated scan — no session supplied"
    if victim.configured:
        return ("Authenticated scan with two accounts — access-control testing "
                "enabled (Attacker A vs Victim B)")
    return ("Authenticated scan with one account — supply a second session to "
            "enable access-control (IDOR) testing")
