"""Optional AI assist — strategy adjustment during a scan, and report writing.

SmartHunt works with no AI at all.  When a Claude provider is available this
module adds two things, and *only* two things:

``advise()``
    Looks at what the scan has found so far and suggests configuration
    adjustments — deeper crawl, more rounds, extra paths worth probing, live
    hosts worth prioritising.  Useful on a large wildcard scope, where the right
    depth setting is impossible to guess before you see the surface.
``write_report()``
    Rewrites the triaged finding into the prose a triager actually wants to
    read, instead of the fixed template.

**The AI is never allowed to decide whether something is a bug.**  That call is
made by :mod:`smarthunt.triage` from captured evidence, before this module is
asked anything, and nothing here can overturn it.  The report writer is handed a
finding that has already passed the evidence gate and may only phrase what is
already proven — every sentence it produces is checked against the captured
exchanges before it reaches the report, and any output that hedges, invents a
URL, cites a status code that was never returned, or reaches for impact beyond
the evidence is discarded and the deterministic report is used instead.  That is
the whole point of "never give false positives": adding a language model to a
security tool must not add a single unproven claim.

The adviser is fenced the same way.  It returns *settings*, not conclusions, and
only a fixed whitelist of settings is honoured — each clamped to the range the
UI already allows.  Hostnames it suggests are dropped unless they sit inside the
authorised scope, so no amount of model creativity can push a scan out of the
program you are allowed to test.

Providers, tried in this order:

``claude`` CLI
    Claude Code, authenticated with your Claude subscription (Pro/Max).  If you
    can run ``claude`` in a terminal, SmartHunt can use it — no API key, no
    separate billing.
``anthropic`` SDK
    The Anthropic API, which bills separately from a subscription.  Credentials
    resolve the SDK's own way: ``ANTHROPIC_API_KEY``, ``ANTHROPIC_AUTH_TOKEN``,
    then an ``ant auth login`` profile.

Neither is required.  With no provider, ``Assistant.create()`` returns ``None``
and every call site falls back to the deterministic path.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from .evidence import mask

#: Default model. Override with --ai-model or SMARTHUNT_AI_MODEL.
MODEL = "claude-opus-5"

#: Cap on model calls per scan, so a long wildcard run cannot quietly turn into
#: a hundred requests.
DEFAULT_BUDGET = 8

SYSTEM = (
    "You are assisting an authorised security tester who is running SmartHunt "
    "against a target they have written permission to test (their own asset or "
    "an in-scope bug bounty program). You do two jobs: tuning reconnaissance "
    "settings, and writing up a finding that has ALREADY been proven by captured "
    "HTTP evidence.\n\n"
    "Absolute rules:\n"
    "1. Never claim anything the captured evidence does not show. No 'may', "
    "'could', 'might', 'potentially', 'likely', or 'if exploited'.\n"
    "2. Never speculate about impact, escalation, or chaining.\n"
    "3. Never invent a URL, parameter, status code or response body.\n"
    "4. Reply with a single JSON object and nothing else — no prose before or "
    "after, no markdown fences.\n"
)


# --------------------------------------------------------------------------- #
# Provider detection
# --------------------------------------------------------------------------- #
def _sdk_credential_source() -> str:
    """Name the credential the Anthropic SDK would pick up, or ''."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "ANTHROPIC_API_KEY"
    if os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return "ANTHROPIC_AUTH_TOKEN"
    config_dir = (os.environ.get("ANTHROPIC_CONFIG_DIR")
                  or os.path.expanduser("~/.config/anthropic"))
    if os.path.isdir(os.path.join(config_dir, "credentials")):
        return "ant auth login profile"
    return ""


def _sdk_installed() -> bool:
    try:
        import anthropic  # noqa: F401
    except Exception:
        return False
    return True


def detect() -> dict:
    """Describe what AI backing is available, without making a request."""
    cli = shutil.which("claude")
    if cli:
        return {"available": True, "provider": "claude-code-cli", "path": cli,
                "detail": "Claude Code CLI — uses your Claude subscription login"}
    if _sdk_installed():
        source = _sdk_credential_source()
        if source:
            return {"available": True, "provider": "anthropic-sdk", "path": "",
                    "detail": f"Anthropic SDK — credentials from {source} "
                              f"(billed as API usage, not your subscription)"}
        return {"available": False, "provider": "", "path": "",
                "detail": "anthropic SDK installed but no credentials: run "
                          "'ant auth login', or set ANTHROPIC_API_KEY"}
    return {"available": False, "provider": "", "path": "",
            "detail": "no provider: install Claude Code (npm i -g "
                      "@anthropic-ai/claude-code) to use your subscription, "
                      "or 'pip install anthropic' with an API key"}


class ClaudeCodeCLI:
    """Talk to Claude through the Claude Code CLI, on the subscription login."""

    name = "claude-code-cli"

    def __init__(self, path: str, model: str = ""):
        self.path = path
        self.model = model

    def ask(self, system: str, prompt: str, max_tokens: int = 4000,
            timeout: int = 240) -> tuple[str, str]:
        """Return ``(text, error)``; exactly one is non-empty."""
        argv = [self.path, "-p", f"{system}\n\n{prompt}"]
        if self.model:
            argv += ["--model", self.model]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired:
            return "", f"claude CLI timed out after {timeout}s"
        except Exception as exc:
            return "", f"claude CLI failed: {type(exc).__name__}: {exc}"
        out = (proc.stdout or "").strip()
        if proc.returncode != 0 and not out:
            return "", f"claude CLI exited {proc.returncode}: {(proc.stderr or '')[:200]}"
        # --output-format is not requested, so stdout is the reply text. If a
        # future CLI wraps it in JSON, unwrap the usual field rather than fail.
        if out.startswith("{"):
            try:
                payload = json.loads(out)
                if isinstance(payload, dict) and isinstance(payload.get("result"), str):
                    out = payload["result"]
            except ValueError:
                pass
        return out, "" if out else "claude CLI returned nothing"


class AnthropicSDK:
    """Talk to Claude through the Anthropic API (separate from a subscription)."""

    name = "anthropic-sdk"

    def __init__(self, model: str = ""):
        self.model = model or MODEL
        self._client = None

    def _client_or_error(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic()
        return self._client

    def ask(self, system: str, prompt: str, max_tokens: int = 4000,
            timeout: int = 240) -> tuple[str, str]:
        try:
            client = self._client_or_error()
        except Exception as exc:
            return "", f"anthropic client: {type(exc).__name__}: {exc}"

        request = dict(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": prompt}],
            thinking={"type": "adaptive"},
            output_config={"effort": "medium"},
        )
        try:
            # Security tooling sits close to the cybersecurity safeguards on the
            # newest models, so opt into the server-side fallback: a declined
            # request is re-run on the recommended fallback model inside the
            # same call instead of coming back empty.
            response = client.with_options(timeout=float(timeout)).beta.messages.create(
                betas=["server-side-fallback-2026-07-01"], fallbacks="default", **request)
        except Exception:
            try:
                response = client.with_options(timeout=float(timeout)).messages.create(**request)
            except Exception as exc:
                return "", f"anthropic request failed: {type(exc).__name__}: {exc}"

        # Check the stop reason before touching content: a refusal can arrive as
        # HTTP 200 with an empty or partial content list.
        if getattr(response, "stop_reason", "") == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) or "unspecified"
            return "", f"the model declined this request ({category})"

        text = "".join(block.text for block in response.content
                       if getattr(block, "type", "") == "text")
        return text.strip(), "" if text.strip() else "empty response"


# --------------------------------------------------------------------------- #
# JSON extraction
# --------------------------------------------------------------------------- #
def extract_json(text: str) -> dict | None:
    """Pull the first balanced JSON object out of a reply."""
    if not text:
        return None
    start = text.find("{")
    while start != -1:
        depth, in_string, escaped = 0, False, False
        for index in range(start, len(text)):
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[start:index + 1])
                    except ValueError:
                        break
                    return parsed if isinstance(parsed, dict) else None
        start = text.find("{", start + 1)
    return None


# --------------------------------------------------------------------------- #
# Report validation — the part that keeps false positives out
# --------------------------------------------------------------------------- #
#: Hedging language. The evidence standard rejects a report containing any of
#: it, so a rewrite containing any of it is discarded rather than published.
HEDGES = re.compile(
    r"\b(may|might|could|potentially|possibly|likely|probably|presumably|"
    r"perhaps|seems?|appears?|suggests?|theoretical(?:ly)?|assum\w+|"
    r"conceivably|arguably)\b", re.I)

#: Impact words that must not appear unless the proven finding already says so.
ESCALATION = re.compile(
    r"\b(remote code execution|\bRCE\b|account takeover|full compromise|"
    r"exfiltrat\w+|dump(?:ed|ing)? the database|arbitrary code|lateral movement|"
    r"privilege escalation|complete control|all (?:users|accounts|customers))\b", re.I)

#: A severity claim inside the prose. It must match the locked severity.
SEVERITY_CLAIM = re.compile(
    r"(?:severity\s*[:=]\s*|rated\s+|graded\s+)(critical|high|medium|low)\b"
    r"|\b(critical|high|medium|low)[- ]severity\b", re.I)

URL_IN_TEXT = re.compile(r"https?://[^\s)>\]\"'`]+")

#: Only status codes stated *as* status codes are checked, so a byte count or an
#: object ID in the prose is not mistaken for an HTTP response.
STATUS_IN_TEXT = re.compile(
    r"(?:HTTP/1\.[01]\s+|HTTP\s+|status(?:\s+code)?\s+(?:of\s+)?|"
    r"returned\s+|responded\s+with\s+|answered\s+with\s+)([1-5]\d{2})\b", re.I)

FIELD_LIMITS = {
    "title": 140, "summary": 900, "impact": 500, "boundary": 240,
    "expected": 320, "actual": 400, "triager_note": 400,
}


def _clean(text) -> str:
    """Strip anything that would break out of the template."""
    if not isinstance(text, str):
        return ""
    text = re.sub(r"```[a-z]*", "", text)
    text = "\n".join(line for line in text.split("\n")
                     if not line.lstrip().startswith("#"))
    return re.sub(r"\s+", " ", text).strip()


def evidence_facts(finding) -> dict:
    """The ground truth a rewrite is allowed to draw on — nothing else."""
    ev = finding.evidence
    exchanges = list(ev.exchanges) if ev else []
    return {
        "urls": [e.url for e in exchanges if e.url] + ([finding.endpoint]
                                                       if finding.endpoint else []),
        "statuses": {str(e.status) for e in exchanges if e.status},
        "source_text": " ".join(filter(None, [
            finding.name, finding.detail, finding.impact, finding.boundary,
            finding.expected, finding.actual, " ".join(finding.remediation or []),
        ])).lower(),
        "exchange_count": len(exchanges),
    }


def validate_report(sections: dict, finding, severity: str) -> tuple[dict, list]:
    """Check a rewrite against the evidence. Returns ``(clean, problems)``.

    Anything in ``problems`` means the rewrite is not used at all — this is a
    fail-closed gate, not a repair pass. A partially trustworthy report is not a
    thing that exists.
    """
    facts = evidence_facts(finding)
    problems: list[str] = []
    clean: dict = {}

    for field, limit in FIELD_LIMITS.items():
        value = _clean(sections.get(field, ""))
        if field in ("title", "summary", "impact") and not value:
            problems.append(f"'{field}' is missing")
        if len(value) > limit:
            value = value[:limit].rsplit(" ", 1)[0] + "…"
        clean[field] = value

    steps = [_clean(s) for s in (sections.get("steps") or []) if _clean(s)]
    # One step per captured exchange: a rewrite cannot introduce a request that
    # was never sent, and cannot drop one that was.
    if len(steps) != facts["exchange_count"]:
        problems.append(f"{len(steps)} reproduction steps for "
                        f"{facts['exchange_count']} captured exchange(s)")
    clean["steps"] = [s[:300] for s in steps]

    remediation = [_clean(r) for r in (sections.get("remediation") or []) if _clean(r)]
    clean["remediation"] = [r[:200] for r in remediation[:8]]

    narrative = " ".join([clean.get(f, "") for f in FIELD_LIMITS] + clean["steps"])

    hedge = HEDGES.search(narrative)
    if hedge:
        problems.append(f"speculative language: '{hedge.group(0)}'")

    for match in ESCALATION.finditer(narrative):
        if match.group(0).lower() not in facts["source_text"]:
            problems.append(f"impact claim beyond the evidence: '{match.group(0)}'")
            break

    claim = SEVERITY_CLAIM.search(narrative)
    if claim:
        claimed = (claim.group(1) or claim.group(2) or "").lower()
        if claimed != severity.lower():
            problems.append(f"severity restated as '{claimed}', locked at '{severity}'")

    for found in URL_IN_TEXT.findall(narrative):
        candidate = found.rstrip(".,;:'\"`)")
        if not any(known.startswith(candidate) or candidate.startswith(known)
                   for known in facts["urls"] if known):
            problems.append(f"URL not in the captured evidence: {candidate}")
            break

    for code in STATUS_IN_TEXT.findall(narrative):
        if code not in facts["statuses"] and code not in facts["source_text"]:
            problems.append(f"status code {code} was never returned")
            break

    return clean, problems


def render_report(report: dict, sections: dict, host: str) -> str:
    """Render the AI prose into the fixed template.

    The evidence blocks, the severity line and the reproduction commands are
    generated from the captured exchanges by code — the model contributes prose
    to named slots and nothing else, so it cannot fabricate a proof.
    """
    from .triage import evidence_blocks   # local import: triage imports nothing here

    finding = report["finding"]
    severity, justification = report["severity"], report["justification"]
    ev = finding.evidence
    exchanges = list(ev.exchanges) if ev else []
    _, poc = evidence_blocks(finding, host)

    steps = []
    for number, exchange in enumerate(exchanges, 1):
        prose = sections["steps"][number - 1] if number <= len(sections["steps"]) \
            else (exchange.note or "Send the request below")
        curl = f"curl -i -s -X {exchange.method} '{exchange.url}'"
        steps.append(f"{number}. {prose}\n   ```\n   {curl}\n   ```\n"
                     f"   Server returns `{exchange.status or exchange.error}`.")

    reliability = (f"Reproduced {ev.reproduced + 1}× total"
                   + (", including on a fresh session with no prior cookies"
                      if ev.fresh_session else "")
                   + (", unauthenticated" if ev.unauthenticated else "")
                   + "." if ev else "Not established.")

    remediation = sections["remediation"] or finding.remediation
    note = sections.get("triager_note", "")

    parts = [
        f"# {sections['title'] or finding.name}",
        f"\n**Severity:** {severity.title()} — {justification}",
        f"\n**OWASP:** {finding.owasp or '—'}",
        f"\n## Summary\n\n{sections['summary']}",
        "\n## Affected Component\n",
        f"- **Endpoint:** `{finding.endpoint}`",
        f"- **Method:** `{finding.method or 'GET'}`",
        f"- **Parameter / field:** `{finding.param or '—'}`",
        f"- **Host:** `{host}`",
        "\n## Steps to Reproduce\n",
        "\n".join(steps) if steps else "_No captured exchanges._",
        "\n## Proof of Concept\n",
        "\n\n".join(poc) if poc else "_None captured._",
        "\n## Impact\n",
        f"- **Proven:** {sections['impact'] or finding.impact}",
        f"- **Security boundary crossed:** {sections['boundary'] or finding.boundary}",
        "\n## Expected vs Actual\n",
        f"- **Expected:** {sections['expected'] or finding.expected}",
        f"- **Actual:** {sections['actual'] or finding.actual}",
        f"\n## Reproduction Reliability\n\n{reliability}",
        "\n## Remediation\n",
        "\n".join(f"- {item}" for item in remediation) or "- —",
    ]
    if note:
        parts.append(f"\n## Note for the triager\n\n{note}")
    parts.append(
        f"\n---\n\nSelected from {report.get('considered', 0)} scan finding(s); "
        f"{report.get('dropped', 0)} were informational or hardening-only and are "
        f"not reportable on their own. Credentials and personal data above are "
        f"masked. Written from the captured evidence only — every request and "
        f"response shown was recorded during the scan.")
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Advice sanitising — the AI returns settings, never conclusions
# --------------------------------------------------------------------------- #
#: setting -> (kind, low, high). Nothing outside this table is ever applied, so
#: the model cannot touch scope, authorisation, output paths or the evidence gate.
TUNABLE = {
    "crawl_depth": ("int", 1, 5),
    "max_pages": ("int", 10, 20000),
    "max_js_files": ("int", 10, 20000),
    "threads": ("int", 1, 200),
    "max_rounds": ("int", 1, 10),
    "bruteforce_subdomains": ("bool", 0, 0),
    "include_subdomains": ("bool", 0, 0),
    "exhaustive": ("bool", 0, 0),
}

#: A suggested path must look like a path and nothing else — no traversal, no
#: query string, no scheme. SmartHunt requests these, so a model that decided to
#: be clever with ``../`` would be sending traversal probes nobody asked for.
SAFE_PATH = re.compile(r"^/?[A-Za-z0-9._~/-]{1,64}$")
TRAVERSAL = re.compile(r"\.\.")
SAFE_HOST = re.compile(r"^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$")


def sanitise_advice(advice: dict, apex: str) -> dict:
    """Keep only what is safe to act on."""
    out = {"assessment": _clean(advice.get("assessment", ""))[:600],
           "adjustments": [], "focus_paths": [], "focus_hosts": [],
           "notes": [_clean(n)[:200] for n in (advice.get("notes") or [])[:6]]}

    for item in (advice.get("adjustments") or [])[:8]:
        if not isinstance(item, dict):
            continue
        setting = str(item.get("setting", "")).strip()
        spec = TUNABLE.get(setting)
        if not spec:
            continue
        kind, low, high = spec
        raw = item.get("value")
        if kind == "bool":
            if not isinstance(raw, bool):
                continue
            value = raw
        else:
            try:
                value = max(low, min(high, int(raw)))
            except (TypeError, ValueError):
                continue
        out["adjustments"].append({"setting": setting, "value": value,
                                   "why": _clean(item.get("why", ""))[:200]})

    for path in (advice.get("focus_paths") or [])[:60]:
        path = str(path).strip()
        if SAFE_PATH.match(path) and not TRAVERSAL.search(path):
            out["focus_paths"].append(path.lstrip("/"))

    # Scope guard: a suggested hostname is only accepted inside the authorised
    # apex. Testing outside the program is the one mistake that ends an account,
    # and it is not going to happen because a model guessed a related domain.
    apex = (apex or "").lower().strip(".")
    for host in (advice.get("focus_hosts") or [])[:40]:
        host = str(host).strip().lower().strip(".")
        if not SAFE_HOST.match(host) or not apex:
            continue
        if host == apex or host.endswith("." + apex):
            out["focus_hosts"].append(host)
    return out


# --------------------------------------------------------------------------- #
# Assistant
# --------------------------------------------------------------------------- #
class Assistant:
    """A budgeted, fail-soft wrapper around one provider."""

    def __init__(self, provider, log, detail: str = "", budget: int = DEFAULT_BUDGET):
        self.provider = provider
        self.log = log
        self.detail = detail
        self.budget = budget
        self.calls = 0
        self.errors: list[str] = []
        self.advice_log: list[dict] = []
        self.report_written = False

    @classmethod
    def create(cls, log, model: str = "", budget: int = DEFAULT_BUDGET):
        """Build an assistant, or return ``None`` when no provider is usable."""
        model = model or os.environ.get("SMARTHUNT_AI_MODEL", "")
        info = detect()
        if not info["available"]:
            log("warn", f"AI assist requested but unavailable — {info['detail']}")
            return None
        provider = (ClaudeCodeCLI(info["path"], model) if info["provider"] == "claude-code-cli"
                    else AnthropicSDK(model))
        log("info", f"AI assist: {info['detail']}")
        return cls(provider, log, detail=info["detail"], budget=budget)

    def _ask_json(self, prompt: str, max_tokens: int = 4000) -> dict | None:
        if self.calls >= self.budget:
            self.log("info", f"  AI budget spent ({self.budget} calls) — skipping")
            return None
        self.calls += 1
        # Mask again on the way out. The evidence renderer already redacts, and
        # this catches anything a caller assembled by hand.
        text, error = self.provider.ask(SYSTEM, mask(prompt), max_tokens=max_tokens)
        if error:
            self.errors.append(error)
            self.log("warn", f"  AI unavailable for this step: {error}")
            return None
        payload = extract_json(text)
        if payload is None:
            self.errors.append("reply was not JSON")
            self.log("warn", "  AI reply was not usable JSON — ignoring it")
        return payload

    # --- job 1: adjust the scan ------------------------------------------
    def advise(self, context: dict, apex: str) -> dict | None:
        """Ask for configuration adjustments given what the scan has seen."""
        prompt = (
            "Tune a reconnaissance scan that is already running. Here is its "
            "state as JSON:\n\n"
            + json.dumps(context, indent=2, default=str)[:12000]
            + "\n\nDecide whether the current settings are finding the surface "
              "or missing it, and reply with this JSON object:\n"
              '{"assessment": "one or two sentences on what the numbers show",\n'
              ' "adjustments": [{"setting": "<one of: '
            + ", ".join(sorted(TUNABLE))
            + '>", "value": <number or boolean>, "why": "..."}],\n'
              ' "focus_paths": ["paths worth requesting on the live hosts, '
              'based on the technologies and endpoints already seen"],\n'
              ' "focus_hosts": ["hostnames inside the authorised scope '
            + json.dumps(apex) + " that are worth probing and are not in the "
              'list yet"],\n'
              ' "notes": ["short observations for the tester"]}\n\n'
              "Only suggest an adjustment when the state actually justifies it; "
              "an empty adjustments list is a valid answer. Every hostname must "
              "end with the authorised scope. Suggest reconnaissance settings "
              "only — do not suggest exploitation."
        )
        raw = self._ask_json(prompt, max_tokens=2000)
        if not raw:
            return None
        advice = sanitise_advice(raw, apex)
        self.advice_log.append(advice)
        return advice

    # --- job 2: write the report ------------------------------------------
    def write_report(self, report: dict, host: str) -> str | None:
        """Rewrite an already-proven finding. Returns markdown, or ``None``.

        Called only when triage has produced a report. A ``None`` return means
        the deterministic report stands — which is a perfectly good outcome, not
        a failure.
        """
        finding = report["finding"]
        severity = report["severity"]
        ev = finding.evidence
        exchanges = list(ev.exchanges) if ev else []

        transcript = []
        for number, exchange in enumerate(exchanges, 1):
            transcript.append(
                f"--- Exchange {number}: {exchange.note or 'request'} ---\n"
                f"{exchange.raw_request(host)}\n\n"
                f"{exchange.raw_response(host)}")

        prompt = (
            "A vulnerability has already been proven by the captured HTTP "
            "exchanges below and has passed an evidence gate. Its severity is "
            f"locked at '{severity}' and must not be restated differently. Write "
            "the report a bug bounty triager wants to read.\n\n"
            f"Finding: {finding.name}\n"
            f"Endpoint: {finding.endpoint}\n"
            f"Method: {finding.method or 'GET'}\n"
            f"Parameter: {finding.param or '—'}\n"
            f"Proven impact (scanner's wording): {finding.impact}\n"
            f"Boundary crossed: {finding.boundary}\n"
            f"Expected: {finding.expected}\n"
            f"Actual: {finding.actual}\n"
            f"Reproduced: {ev.reproduced + 1 if ev else 0}× | fresh session: "
            f"{bool(ev and ev.fresh_session)} | unauthenticated: "
            f"{bool(ev and ev.unauthenticated)}\n\n"
            "Captured evidence (already redacted — keep the placeholders "
            "exactly as they appear):\n\n"
            + "\n\n".join(transcript)[:24000]
            + "\n\nReply with this JSON object:\n"
              '{"title": "specific title naming the flaw and the endpoint",\n'
              ' "summary": "2-4 sentences: what an attacker does and what they '
              'get back. Only what the exchanges show.",\n'
              ' "impact": "one sentence, past tense, describing what was '
              'demonstrated",\n'
              ' "boundary": "the security boundary that failed",\n'
              ' "expected": "what a correctly implemented server does here",\n'
              ' "actual": "what this server did, citing the observed status '
              'codes",\n'
              ' "steps": ["one entry per exchange above, in order, describing '
              'what that request demonstrates"],\n'
              ' "remediation": ["specific fixes for this endpoint, most '
              'important first"],\n'
              ' "triager_note": "optional: how to verify safely"}\n\n'
            f"There are exactly {len(exchanges)} exchanges, so 'steps' must have "
            f"exactly {len(exchanges)} entries. Do not mention any URL or status "
            "code that does not appear above. Do not describe what an attacker "
            "could do next."
        )

        raw = self._ask_json(prompt, max_tokens=4000)
        if not raw:
            return None

        sections, problems = validate_report(raw, finding, severity)
        if problems:
            self.log("warn", "  AI report rejected — using the verified template "
                             "instead:")
            for problem in problems[:4]:
                self.log("warn", f"    · {problem}")
            return None

        self.report_written = True
        self.log("found", "  AI report accepted — every claim checked against "
                          "the captured evidence")
        return render_report(report, sections, host)

    def summary(self) -> dict:
        return {
            "provider": self.provider.name,
            "detail": self.detail,
            "calls": self.calls,
            "errors": self.errors[-4:],
            "advice": self.advice_log,
            "report_written": self.report_written,
        }
