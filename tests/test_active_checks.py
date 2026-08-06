"""The false-positive killer, tested against traps.

Every active check must FIRE on a real vulnerability and stay SILENT on the
false-positive trap sitting next to it: a server that errors on any odd input,
a reflection that lands in an inert context, a page that coincidentally contains
the SSTI product, and an endpoint that returns /etc/passwd for every filename.

Run standalone (no pytest needed):  python3 tests/test_active_checks.py
"""
from __future__ import annotations

import http.server
import os
import re
import socketserver
import sys
import threading
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smarthunt import owasp                     # noqa: E402
from smarthunt.evidence import capture          # noqa: E402
from smarthunt.modules import make_session      # noqa: E402
from smarthunt.owasp import _mutate             # noqa: E402


def _send(handler, code, ctype, data: bytes):
    handler.send_response(code)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class _Trap(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        parts = urlparse(self.path)
        q = parse_qs(parts.query, keep_blank_values=True)
        path = parts.path

        if path == "/sqli":                       # REAL: odd quotes break, balanced recover
            v = q.get("id", [""])[0]
            if v.count("'") % 2 == 1:
                return _send(self, 500, "text/html",
                             b"You have an error in your SQL syntax; check the manual "
                             b"that corresponds to your MySQL server version")
            return _send(self, 200, "application/json", b'{"id":1}')

        if path == "/sqli_trap":                  # TRAP: errors on any non-numeric input
            v = q.get("id", [""])[0]
            if v and not v.isdigit():
                return _send(self, 500, "text/html",
                             b"You have an error in your SQL syntax; check the manual "
                             b"that corresponds to your MySQL server version")
            return _send(self, 200, "application/json", b'{"id":1}')

        if path == "/xss":                        # REAL: reflects into live HTML body
            v = q.get("q", [""])[0]
            return _send(self, 200, "text/html",
                         f"<html><body><h1>{v}</h1></body></html>".encode())

        if path == "/xss_trap":                   # TRAP: reflects only inside <textarea>
            v = q.get("q", [""])[0]
            return _send(self, 200, "text/html",
                         f"<html><body><textarea>{v}</textarea></body></html>".encode())

        if path == "/ssti":                       # REAL: evaluates {{a*b}}
            v = q.get("name", [""])[0]
            m = re.fullmatch(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", v)
            out = str(int(m.group(1)) * int(m.group(2))) if m else v
            return _send(self, 200, "text/html", f"<p>Hello {out}</p>".encode())

        if path == "/ssti_trap":                  # TRAP: always contains 49, never evaluates
            v = q.get("name", [""])[0]
            return _send(self, 200, "text/html", f"<p>Order 49 for {v}</p>".encode())

        if path == "/dl":                         # REAL: traversal returns passwd
            f = q.get("file", [""])[0]
            if "etc/passwd" in f.replace("%2f", "/"):
                return _send(self, 200, "text/plain",
                             b"root:x:0:0:root:/root:/bin/bash\n")
            return _send(self, 200, "text/plain", b"normal file contents")

        if path == "/dl_trap":                     # TRAP: passwd-looking body for everything
            return _send(self, 200, "text/plain",
                         b"# passwd format docs:\nroot:x:0:0:root:/root:/bin/bash\n")

        return _send(self, 404, "text/plain", b"not found")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run() -> int:
    server = _Server(("127.0.0.1", 0), _Trap)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    session = make_session()
    log = lambda *a: None
    fails = []

    def baseline(path, param):
        return capture(session, "GET", _mutate(f"{base}{path}?{param}=x", param, "1"),
                       note="baseline")

    def check(name, cond, extra=""):
        print(("  PASS  " if cond else "  FAIL  ") + name + (f"   {extra}" if extra else ""))
        if not cond:
            fails.append(name)

    # ``control_exchange`` is False for XSS: its differential is an in-response
    # context check (is the reflection inside a live context?), not a separate
    # control request, so it legitimately captures no extra exchange.
    cases = [
        ("SQLi", owasp._check_sqli, "/sqli", "/sqli_trap", "id", "errors on everything", True),
        ("XSS", owasp._check_xss, "/xss", "/xss_trap", "q", "inert <textarea>", False),
        ("SSTI", owasp._check_ssti, "/ssti", "/ssti_trap", "name", "coincidental 49", True),
        ("Traversal", owasp._check_traversal, "/dl", "/dl_trap", "file", "passwd for everything", True),
    ]
    for label, fn, real, trap, param, why, control_exchange in cases:
        print(f"== {label} ==")
        got = fn(session, f"{base}{real}?{param}=x", param, baseline(real, param), log)
        check(f"{label}: REAL fires", got is not None)
        if got is not None:
            notes = " ".join(e.note.lower() for e in got.evidence.exchanges)
            if control_exchange:
                check(f"{label}: evidence carries a control exchange",
                      "control" in notes or "confirm" in notes, notes[:80])
            check(f"{label}: reproduced >= 1", got.evidence.reproduced >= 1)
        got = fn(session, f"{base}{trap}?{param}=x", param, baseline(trap, param), log)
        check(f"{label}: TRAP ({why}) rejected", got is None)

    server.shutdown()
    print("\n" + ("ALL PASSED" if not fails else f"{len(fails)} FAILURES: {fails}"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
