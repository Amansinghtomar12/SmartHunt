"""Local web front-end for SmartHunt.

Runs the same :class:`~smarthunt.engine.Scanner` as the desktop GUI, but drives
it from a browser — useful when hunting from a VPS over SSH, or when Tkinter
isn't available.

    python smarthunt.py --web            ->  http://127.0.0.1:8777

Built on :mod:`http.server` so there is no extra dependency.

Because this server can launch scans and write files, and it lives on an origin
every page in your browser can reach, it defends itself on three fronts:

* ``Host`` must be a loopback name — blocks DNS rebinding, where an attacker
  points ``evil.com`` at 127.0.0.1 to get same-origin access.
* every mutating request must carry ``X-SmartHunt-Token``, a per-process secret
  stamped into ``index.html``.  A custom header forces a CORS preflight, which
  this server never approves, so a cross-origin page cannot even send the
  request — let alone guess the token.
* an ``Origin`` header, when present, must match our own.

Without the token check a page on any site you happened to be visiting could
POST ``Content-Type: text/plain`` here (a CORS "simple request", so no preflight)
and start scans from your machine against a target of its choosing.  It could
not read the reply, but the traffic would still be yours.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__, report
from .engine import (DEFAULT_ENABLED, STAGES, STAGE_TITLES, ScanConfig, Scanner,
                     normalize_target)
from .tools import CATEGORIES, REGISTRY, detect_tools

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

#: Host header values we accept. Anything else is a possible rebinding attempt.
_LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

#: Per-process CSRF secret, stamped into index.html and required on every POST.
CSRF_TOKEN = secrets.token_urlsafe(24)
_TOKEN_PLACEHOLDER = "__SMARTHUNT_TOKEN__"

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}

MAX_EVENTS = 20000  # ring-buffer cap so a long scan can't exhaust memory


class ScanSession:
    """Holds the single active scan and buffers its events for polling."""

    def __init__(self):
        self.lock = threading.RLock()
        self.scanner: Scanner | None = None
        self.events: list[dict] = []
        self.dropped_events = 0
        self.stage_states: dict[str, str] = {}
        self.progress = 0.0
        self.results = None
        self.error: str | None = None
        self.started = 0.0
        self.finished = 0.0
        self.target = ""
        self.mode = ""
        self.inventory = detect_tools()
        self.export_dir: str | None = None
        self.report_path: str | None = None
        # Bumped per scan so a client can tell its buffered log/results apart
        # from a run someone started in another tab.
        self.run_id = 0

    # --- scanner callbacks (called from the scan thread) ------------------
    def _on_log(self, level, message):
        with self.lock:
            self.events.append({
                "i": len(self.events) + self.dropped_events,
                "level": level,
                "msg": message,
                "ts": time.strftime("%H:%M:%S"),
            })
            if len(self.events) > MAX_EVENTS:
                overflow = len(self.events) - MAX_EVENTS
                del self.events[:overflow]
                self.dropped_events += overflow

    def _on_stage(self, key, state):
        with self.lock:
            self.stage_states[key] = state

    def _on_progress(self, done, total):
        with self.lock:
            self.progress = (done / total * 100.0) if total else 0.0

    def _on_done(self, results, error):
        with self.lock:
            self.results = results
            self.error = str(error) if error else None
            self.finished = time.time()
            self.progress = 100.0

    # --- control ----------------------------------------------------------
    def start(self, config: ScanConfig):
        with self.lock:
            if self.scanner and self.scanner.running:
                raise RuntimeError("a scan is already running")
            self.events = []
            self.dropped_events = 0
            self.stage_states = {}
            self.progress = 0.0
            self.results = None
            self.error = None
            self.started = time.time()
            self.finished = 0.0
            self.target = config.target
            self.mode = config.mode
            self.export_dir = None
            self.report_path = None
            self.run_id += 1
            self.scanner = Scanner(
                config, inventory=self.inventory,
                on_log=self._on_log, on_stage=self._on_stage,
                on_progress=self._on_progress, on_done=self._on_done,
            )
            self.scanner.start()

    def stop(self):
        with self.lock:
            if self.scanner:
                self.scanner.stop()

    def set_paused(self, paused: bool):
        with self.lock:
            if not self.scanner:
                return
            if paused:
                self.scanner.pause()
            else:
                self.scanner.resume()

    # --- reads ------------------------------------------------------------
    def status(self) -> dict:
        with self.lock:
            running = bool(self.scanner and self.scanner.running)
            paused = bool(self.scanner and self.scanner.pause_event.is_set())
            stopped = bool(self.scanner and self.scanner.stop_event.is_set())
            elapsed = ((self.finished or time.time()) - self.started) if self.started else 0.0
            return {
                "running": running,
                "paused": paused,
                "stopped": stopped,
                "progress": round(self.progress, 1),
                "stages": dict(self.stage_states),
                "elapsed": round(elapsed, 1),
                "target": self.target,
                "mode": self.mode,
                "error": self.error,
                "has_results": self.results is not None,
                "stats": self.results.stats() if self.results else {},
                "next_event": len(self.events) + self.dropped_events,
                "run": self.run_id,
                "export_dir": self.export_dir,
                "report_ready": bool(self.report_path),
            }

    def events_since(self, cursor: int, limit: int = 500) -> dict:
        with self.lock:
            base = self.dropped_events
            start = max(0, cursor - base)
            chunk = self.events[start:start + limit]
            return {
                "events": chunk,
                "cursor": (chunk[-1]["i"] + 1) if chunk
                          else max(cursor, base + len(self.events)),
                "dropped": base,
            }

    def results_payload(self) -> dict:
        with self.lock:
            if not self.results:
                return {"ready": False}
            data = asdict(self.results)
            data["ready"] = True
            data["stats"] = self.results.stats()
            data["duration"] = round(self.results.duration, 1)
            return data

    def export(self, outdir: str) -> dict:
        with self.lock:
            if not self.results:
                raise RuntimeError("no results to export")
            results = self.results
            target_dir = os.path.join(outdir, results.target.replace(".", "_"))
        written = report.export_all(results, target_dir)
        with self.lock:
            self.export_dir = target_dir
            self.report_path = next((p for p in written if p.endswith(".html")), None)
        return {"dir": target_dir, "files": written, "report": self.report_path}


SESSION = ScanSession()


def _stage_catalog() -> list[dict]:
    return [
        {
            "key": key,
            "title": title,
            "modes": list(modes),
            "default_domain": key in DEFAULT_ENABLED["domain"],
            "default_wildcard": key in DEFAULT_ENABLED["wildcard"],
        }
        for key, title, modes in STAGES
    ]


def _tool_catalog(inv) -> list[dict]:
    return [
        {
            "name": t.name,
            "category": t.category,
            "description": t.description,
            "install": t.install,
            "installed": inv.has(t.name),
        }
        for t in REGISTRY
    ]


class Handler(BaseHTTPRequestHandler):
    """Routes API calls and serves the single-page front-end."""

    server_version = f"SmartHunt/{__version__}"
    protocol_version = "HTTP/1.1"

    # --- helpers ----------------------------------------------------------
    def log_message(self, fmt, *args):  # quieter than the default
        if os.environ.get("SMARTHUNT_WEB_DEBUG"):
            super().log_message(fmt, *args)

    def _host_ok(self) -> bool:
        """Reject anything but a loopback Host — the DNS-rebinding guard."""
        raw = (self.headers.get("Host") or "").strip()
        if not raw:
            return True  # curl -H 'Host;' and friends; no browser origin to abuse
        if raw.startswith("["):                       # [::1] or [::1]:8777
            host = raw[1:].split("]", 1)[0]
        else:
            host = raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw
        return host.lower() in _LOOPBACK_NAMES

    def _origin_ok(self) -> bool:
        """A cross-origin page must not be able to drive this server."""
        origin = self.headers.get("Origin")
        if not origin or origin == "null":
            return True  # same-origin fetches from our own page send no Origin
        hostname = urlparse(origin).hostname or ""
        return hostname.lower().strip("[]") in _LOOPBACK_NAMES

    def _csrf_ok(self) -> bool:
        """Require the per-process token that only our own page has been given."""
        return secrets.compare_digest(
            self.headers.get("X-SmartHunt-Token") or "", CSRF_TOKEN)

    def _send(self, code, body: bytes, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, payload, code=200):
        self._send(code, json.dumps(payload, default=str).encode("utf-8"))

    def _error(self, code, message):
        self._json({"error": message}, code=code)

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0 or length > 2_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def _serve_static(self, rel_path: str):
        rel_path = rel_path.lstrip("/") or "index.html"
        full = os.path.normpath(os.path.join(WEB_DIR, rel_path))
        # Containment check — never serve outside the bundled web directory.
        if os.path.commonpath([os.path.realpath(full), os.path.realpath(WEB_DIR)]) != \
                os.path.realpath(WEB_DIR):
            return self._error(403, "forbidden")
        if not os.path.isfile(full):
            return self._error(404, "not found")
        ext = os.path.splitext(full)[1].lower()
        with open(full, "rb") as fh:
            body = fh.read()
        if ext == ".html":
            body = body.replace(_TOKEN_PLACEHOLDER.encode(), CSRF_TOKEN.encode())
        self._send(200, body, _CONTENT_TYPES.get(ext, "application/octet-stream"))

    # --- routing ----------------------------------------------------------
    def do_GET(self):
        if not self._host_ok():
            return self._error(403, "invalid Host header")
        url = urlparse(self.path)
        path = url.path
        query = parse_qs(url.query)

        if path in ("/", "/index.html"):
            return self._serve_static("index.html")
        if path.startswith("/static/"):
            return self._serve_static(path[len("/static/"):])

        if path == "/api/meta":
            inv = SESSION.inventory
            return self._json({
                "version": __version__,
                "stages": _stage_catalog(),
                "tools": _tool_catalog(inv),
                "categories": CATEGORIES,
                "tools_found": len(inv.available),
                "tools_total": len(REGISTRY),
                "cwd": os.getcwd(),
                "default_out": os.path.join(os.getcwd(), "smarthunt-results"),
            })
        if path == "/api/status":
            return self._json(SESSION.status())
        if path == "/api/events":
            try:
                cursor = int(query.get("cursor", ["0"])[0])
            except ValueError:
                cursor = 0
            return self._json(SESSION.events_since(max(0, cursor)))
        if path == "/api/results":
            return self._json(SESSION.results_payload())
        if path == "/api/rescan-tools":
            SESSION.inventory = detect_tools()
            return self._json({"tools": _tool_catalog(SESSION.inventory),
                               "tools_found": len(SESSION.inventory.available)})
        if path == "/report":
            with SESSION.lock:
                report_path = SESSION.report_path
            if not report_path or not os.path.isfile(report_path):
                return self._error(404, "no report exported yet")
            with open(report_path, "rb") as fh:
                return self._send(200, fh.read(), "text/html; charset=utf-8")

        return self._error(404, "not found")

    def do_OPTIONS(self):
        # Answer preflights with a plain 403 and no CORS headers, so the browser
        # refuses the cross-origin request it was checking on behalf of.
        self._error(403, "cross-origin requests are not allowed")

    def do_POST(self):
        if not self._host_ok():
            return self._error(403, "invalid Host header")
        if not self._origin_ok():
            return self._error(403, "cross-origin requests are not allowed")
        body = self._read_json()  # drain first: a keep-alive connection is reused
        if not self._csrf_ok():
            return self._error(403, "missing or invalid X-SmartHunt-Token")
        path = urlparse(self.path).path

        if path == "/api/scan/start":
            return self._start_scan(body)
        if path == "/api/scan/stop":
            SESSION.stop()
            return self._json({"ok": True})
        if path == "/api/scan/pause":
            SESSION.set_paused(bool(body.get("paused", True)))
            return self._json({"ok": True})
        if path == "/api/export":
            outdir = str(body.get("out") or os.path.join(os.getcwd(), "smarthunt-results"))
            try:
                return self._json(SESSION.export(outdir))
            except Exception as exc:
                return self._error(400, str(exc))

        return self._error(404, "not found")

    def _start_scan(self, body):
        raw_target = str(body.get("target", "")).strip()
        try:
            detected_mode, apex = normalize_target(raw_target)
        except ValueError as exc:
            return self._error(400, str(exc))

        mode = str(body.get("mode") or detected_mode)
        if mode not in ("domain", "wildcard"):
            mode = detected_mode
        if detected_mode == "wildcard":
            mode = "wildcard"

        if not body.get("authorized"):
            return self._error(400, "authorization must be confirmed before scanning")

        valid = {k for k, _, modes in STAGES if mode in modes}
        requested = {str(s) for s in (body.get("stages") or [])}
        stages = requested & valid
        if not stages:
            return self._error(400, "enable at least one module for this mode")

        def as_int(key, default, lo, hi):
            try:
                return max(lo, min(hi, int(body.get(key, default))))
            except (TypeError, ValueError):
                return default

        ports = []
        for chunk in str(body.get("ports", "")).replace(" ", "").split(","):
            if chunk.isdigit() and 0 < int(chunk) < 65536:
                ports.append(int(chunk))

        config = ScanConfig(
            target=apex, mode=mode, enabled_stages=stages,
            threads=as_int("threads", 40, 1, 500),
            crawl_depth=as_int("depth", 2, 1, 5),
            max_pages=as_int("max_pages", 300, 10, 20000),
            max_js_files=as_int("max_js", 400, 10, 20000),
            include_subdomains=bool(body.get("include_subs", True)),
            bruteforce_subdomains=bool(body.get("bruteforce", True)),
            nuclei_severity=str(body.get("severity") or "low,medium,high,critical"),
            subdomain_wordlist=str(body.get("sub_wordlist") or ""),
            content_wordlist=str(body.get("content_wordlist") or ""),
            ports=ports,
            output_dir=str(body.get("out") or os.path.join(os.getcwd(), "smarthunt-results")),
            authorized=True,
            exhaustive=bool(body.get("exhaustive", False)),
            max_rounds=as_int("rounds", 4, 1, 10),
            collaborator=str(body.get("collaborator") or ""),
        )
        try:
            SESSION.start(config)
        except RuntimeError as exc:
            return self._error(409, str(exc))
        return self._json({"ok": True, "target": apex, "mode": mode,
                           "stages": sorted(stages)})


def serve(host: str = "127.0.0.1", port: int = 8777, open_browser: bool = False):
    """Start the web UI and block until interrupted."""
    if not os.path.isdir(WEB_DIR):
        raise SystemExit(f"web assets missing: {WEB_DIR}")

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '') else host}:{port}"

    inv = SESSION.inventory
    print(f"\n  SmartHunt v{__version__} — web UI")
    print(f"  {inv.summary()}")
    print(f"\n  ▶  {url}\n")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNING: bound to a non-loopback address. Anyone who can reach this\n"
              "  port can launch scans from your machine. Use 127.0.0.1 unless you\n"
              "  have deliberately firewalled it.\n")
    print("  Press Ctrl+C to stop.\n")

    if open_browser:
        threading.Timer(0.8, lambda: __import__("webbrowser").open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  shutting down…")
        SESSION.stop()
        httpd.shutdown()
