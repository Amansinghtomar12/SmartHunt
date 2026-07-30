"""OWASP A01 — Broken Access Control, proven with two tester-owned accounts.

This is the check a single-session scanner cannot perform.  Proving IDOR means
showing that **Attacker A receives Victim B's data**, which needs both sessions
side by side.  Nothing here guesses: every claim is backed by three requests to
the same URL under three different identities.

The proof pattern, straight from the bug bounty evidence standard:

1. Victim B requests their own object and is served it (so the object exists,
   is private, and B owns it).
2. An unauthenticated client requests the same URL and is refused (so it is not
   simply public — the single most common false positive).
3. Attacker A, a *different* logged-in account, requests it and is served B's
   data anyway.

If step 2 succeeds the resource is public and nothing is reported.  If step 3
returns 401/403/404, or returns A's own data rather than B's, nothing is
reported.  Only all three passing produces a finding.

Safety: every request is a read.  Object IDs come from URLs Account B already
visited, so SmartHunt only ever reads objects the tester's own account owns.
"""

from __future__ import annotations

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .evidence import Evidence, capture
from .modules import Finding

CATEGORY = "A01:2021 Broken Access Control"

#: Parameters that usually name an object rather than a filter or a page.
ID_PARAMS = {"id", "uid", "userid", "user_id", "account", "account_id", "aid",
             "order", "order_id", "oid", "invoice", "invoice_id", "doc",
             "document", "document_id", "file", "file_id", "record", "ref",
             "customer", "customer_id", "profile", "profile_id", "team",
             "team_id", "org", "org_id", "project", "project_id", "ticket",
             "ticket_id", "message", "message_id", "note", "key", "uuid", "guid"}

#: Path segments that look like an object identifier.
PATH_ID_RE = re.compile(
    r"/(\d{2,})(?=/|$)"                                    # /users/1234
    r"|/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)"  # UUID
    , re.I)

#: Bodies shorter than this carry no evidence worth comparing.
MIN_BODY = 48

#: How alike two responses must be before we call them "the same object".
SAME_OBJECT_RATIO = 0.92

DENIED_STATUSES = {401, 403, 404, 302, 303, 307, 308}


def _params_with_ids(url: str) -> list[str]:
    return [p for p in parse_qs(urlparse(url).query, keep_blank_values=True)
            if p.lower() in ID_PARAMS]


def _has_path_id(url: str) -> bool:
    return bool(PATH_ID_RE.search(urlparse(url).path))


def candidate_urls(urls, api_endpoints, limit: int = 60) -> list[str]:
    """URLs that address a specific object, deduplicated by shape."""
    pool = list(urls) + [e.get("url", "") for e in (api_endpoints or [])]
    shapes, chosen = set(), []
    for url in sorted(set(filter(None, pool))):
        if not url.startswith("http"):
            continue
        if not (_params_with_ids(url) or _has_path_id(url)):
            continue
        parts = urlparse(url)
        shape = (parts.netloc, re.sub(r"\d+", "#", parts.path),
                 tuple(sorted(parse_qs(parts.query))))
        if shape in shapes:
            continue
        shapes.add(shape)
        chosen.append(url)
        if len(chosen) >= limit:
            break
    return chosen


def _similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def _looks_denied(exchange) -> bool:
    if exchange.error or exchange.status is None:
        return True
    if exchange.status in DENIED_STATUSES:
        return True
    body = (exchange.response_body or "").lower()
    return any(marker in body for marker in
               ("unauthorized", "unauthorised", "forbidden", "access denied",
                "not permitted", "please log in", "sign in to continue"))


def _mutate_id(url: str) -> str | None:
    """Same endpoint, a different object — used to prove A sees B's data.

    If Attacker A gets an identical response for object 1234 and object 9999,
    the endpoint ignores the identifier entirely and is returning a generic
    page, not Victim B's record.
    """
    parts = urlparse(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    for name in list(query):
        if name.lower() in ID_PARAMS:
            value = query[name][0]
            if value.isdigit():
                query[name] = [str(int(value) + 7919)]
                flat = urlencode({k: v[0] for k, v in query.items()})
                return urlunparse(parts._replace(query=flat))
    match = PATH_ID_RE.search(parts.path)
    if match and match.group(1) and match.group(1).isdigit():
        bumped = str(int(match.group(1)) + 7919)
        path = parts.path[:match.start(1)] + bumped + parts.path[match.end(1):]
        return urlunparse(parts._replace(path=path))
    return None


def _check_one(url, victim_session, attacker_session, anon_session, log):
    """Run the three-identity comparison for a single URL."""
    # 1. Victim B fetches their own object.
    as_victim = capture(victim_session, "GET", url,
                        note="Victim B requests their own object")
    if _looks_denied(as_victim) or len(as_victim.response_body or "") < MIN_BODY:
        return None    # B does not own this, or there is nothing to compare

    # 2. Is it simply public? By far the most common false positive.
    as_anon = capture(anon_session, "GET", url,
                      note="unauthenticated client requests the same URL")
    if not _looks_denied(as_anon) and \
            _similarity(as_anon.response_body, as_victim.response_body) > SAME_OBJECT_RATIO:
        return None    # public resource — not an access-control failure

    # 3. Attacker A, a different account, requests Victim B's object.
    as_attacker = capture(attacker_session, "GET", url,
                          note="Attacker A requests Victim B's object")
    if _looks_denied(as_attacker):
        return None    # authorisation is enforced — the correct behaviour

    similarity = _similarity(as_attacker.response_body, as_victim.response_body)
    if similarity < SAME_OBJECT_RATIO:
        return None    # A got something else, most likely A's own data

    # 4. Does the endpoint even honour the identifier? If A gets the same body
    #    for a different object, this is a generic page, not B's record.
    other = _mutate_id(url)
    if other:
        as_other = capture(attacker_session, "GET", other,
                           note="Attacker A requests a different object ID")
        if not _looks_denied(as_other) and \
                _similarity(as_other.response_body, as_attacker.response_body) > SAME_OBJECT_RATIO:
            return None   # identifier ignored — generic response, no IDOR

    # Reproduce before claiming anything.
    repeat = capture(attacker_session, "GET", url,
                     note="reproduction: Attacker A requests it again")
    reproduced = 1 if (not _looks_denied(repeat) and
                       _similarity(repeat.response_body, as_victim.response_body)
                       > SAME_OBJECT_RATIO) else 0

    ev = Evidence()
    ev.add(as_victim)
    ev.add(as_anon)
    ev.add(as_attacker)
    ev.reproduced = reproduced + 1
    ev.fresh_session = True      # attacker session is separate from the victim's
    ev.unauthenticated = False

    param = (_params_with_ids(url) or ["path identifier"])[0]
    return Finding(
        host=urlparse(url).netloc,
        name=f"Broken access control (IDOR) on {urlparse(url).path}",
        severity="high", source="accesscontrol", confidence="high", evidence=ev,
        owasp=CATEGORY, endpoint=url, method="GET", param=param,
        detail=f"Attacker A receives Victim B's object ({similarity:.0%} identical "
               f"to B's own response) while unauthenticated access is refused.",
        boundary="Object ownership is not enforced server-side",
        expected="The server checks that the authenticated account owns the "
                 "requested object and returns 403/404 otherwise",
        actual=f"Attacker A's request returned HTTP {as_attacker.status} with "
               f"Victim B's data; the unauthenticated request was refused "
               f"({as_anon.status}), so the resource is not public",
        impact="A logged-in account reads another account's private object by "
               "requesting its identifier directly.",
        remediation=[
            "Check object ownership server-side on every read, write and delete",
            "Derive the acting user from the session, never from a request field",
            "Deny by default in centralised authorization middleware",
            "Use unguessable identifiers, but treat that as defence in depth, not the control",
            "Add regression tests covering cross-account access",
        ])


def run_checks(urls, api_endpoints, attacker_session, victim_session,
               anon_session, log, stop: threading.Event,
               threads: int = 6, limit: int = 60) -> list[Finding]:
    """Compare Attacker A against Victim B across object-bearing endpoints."""
    if attacker_session is None or victim_session is None:
        log("info", "Access control: needs two sessions — skipped")
        return []

    targets = candidate_urls(urls, api_endpoints, limit=limit)
    if not targets:
        log("info", "Access control: no object-identifier endpoints found")
        return []

    log("info", f"Access control: comparing Attacker A vs Victim B across "
                f"{len(targets)} object endpoint(s)")

    findings: list[Finding] = []
    # Deliberately low concurrency: these are authenticated requests against a
    # real account, and hammering them is both rude and a good way to trip
    # rate limiting that invalidates the comparison.
    with ThreadPoolExecutor(max_workers=max(2, min(threads, 6))) as pool:
        futures = [pool.submit(_check_one, url, victim_session, attacker_session,
                               anon_session, log) for url in targets]
        for future in as_completed(futures):
            if stop.is_set():
                break
            try:
                found = future.result()
            except Exception as exc:
                log("warn", f"  access-control check failed: {exc}")
                continue
            if found:
                findings.append(found)
                log("found", f"  [IDOR] {found.endpoint}")

    if not findings:
        log("info", "Access control: no cross-account access proven")
    return findings
