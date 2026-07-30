# SmartHunt

A bug-hunting recon suite that ends in **one proven, reportable finding** — not a
list of 30 things you still have to triage yourself.

Point it at a domain or a wildcard, press START, and it runs the full pipeline:
subdomain enumeration, HTTP probing, JavaScript mining, endpoint verification,
content discovery, the OWASP Top 10, known-CVE matching, and — given two
accounts you control — broken access control. Then it applies an evidence gate
to everything it found and writes up the single strongest one, with raw
request/response proof and `curl` reproduction steps.

Desktop app, browser UI, and headless CLI, all over the same engine.

![SmartHunt running a scan](docs/demo.gif)

<sub>A real scan, recorded live: boot sequence, stages turning green as they
complete, counters climbing, then the triaged report. GitHub shows this as an
animation — the static shots further down are the same interface held still.</sub>

---

## Quick start

```bash
git clone https://github.com/Amansinghtomar12/SmartHunt
cd SmartHunt
pip install -r requirements.txt      # just `requests`

python smarthunt.py --web            # browser UI at http://127.0.0.1:8777
python smarthunt.py                  # desktop app
python smarthunt.py --cli example.com
```

**No external tools are required.** SmartHunt ships a pure-Python implementation
of every stage, so a fresh clone produces real results with zero setup. It also
detects and drives **112 optional tools across 20 categories** — see
`install-tools.sh` — and gets faster and deeper with each one you install.

If the desktop app complains about Tkinter:

```bash
sudo apt install python3-tk       # Debian / Ubuntu
sudo dnf install python3-tkinter  # Fedora / RHEL
brew install python-tk            # macOS
```

---

## Two target modes

| Mode | Input | What it does |
|---|---|---|
| **Single Domain** | `example.com` | Deep-dive one host: crawl it, pull every JavaScript file, mine those files for endpoints, parameters and secrets, verify which endpoints are real, then test what it found. |
| **Wildcard** | `*.example.com` | Go wide first — every subdomain source and tool available — then run the *entire* deep-dive against everything that came back alive. |

Typing `*.example.com` switches to wildcard mode automatically.

---

## One reportable bug, not a wall of noise

Every scan ends in a triage stage that applies an evidence gate to the whole
finding set and produces exactly one of three outcomes.

![The triaged report](docs/report.png)

| Outcome | When | What you get |
|---|---|---|
| **Report** | Every evidence field is filled and the behaviour reproduces | One finding, severity graded from proven impact, raw request/response, numbered `curl` steps, remediation |
| **Evidence needed** | Something looks real but a proof is missing | The exact tests still owed — never a half-written report |
| **Nothing reportable** | No candidate clears the gate | "No reportable vulnerability found with the current evidence." |

Two rules do the heavy lifting.

**A large class of scanner output is never a standalone report.** Missing
headers, version banners, `x-powered-by`, exposed Swagger, wildcard CORS,
directory listings, SSRF candidates without a collaborator callback, endpoint
discovery — all filtered, each with its reason logged so you can see the call
being made rather than wondering where a finding went.

**Severity comes from what was proven, not from the bug class.** Error-based SQL
injection proves injection, not data exfiltration, so it grades High rather than
Critical and the report says exactly why. The winner is re-verified at report
time — reproduced twice, retried on a fresh cookie-free session — and
credentials are masked (`DB_PASSWORD=REDACTED_SECRET`) before anything is
written to disk.

The full finding list still exports to JSON and CSV for your own digging. It
just isn't the headline.

> **On false positives.** No tool can promise zero, and one that claims to is
> lying. SmartHunt is built to fail *closed*: it drops what it cannot prove,
> checks the unauthenticated case to kill the "this was public all along"
> mistake, reproduces before reporting, and says "nothing reportable" rather
> than padding the output.

---

## Authenticated testing

Unauthenticated scanning only ever sees the front door. Hand SmartHunt a session
you already have and every stage — crawling, JS collection, content discovery,
the OWASP checks — runs logged in.

```bash
python smarthunt.py --cli target.com \
  --auth-cookie "session=abc123; csrftoken=xyz" \
  --auth-check-url https://target.com/account --auth-check-text "your-username"
```

Sessions can be a `Cookie` value, a bearer token, or a **raw header block pasted
straight from Burp or devtools** — hop-by-hop headers are stripped and `Cookie:`
is split into the jar automatically.

**The session is verified before the scan leans on it.** A stale cookie doesn't
fail loudly: the app serves the login page with HTTP 200 and every finding
afterwards is quietly about that login page. Give a check URL and a string that
only appears when logged in, and SmartHunt says so once, up front.

### Two accounts → proven IDOR

Supply a **second account you also control** and SmartHunt tests OWASP A01,
Broken Access Control — the most common serious bug class, and one no
single-session scanner can prove:

```bash
python smarthunt.py --cli target.com \
  --auth-cookie   "session=ATTACKER_A" \
  --victim-cookie "session=VICTIM_B" \
  --auth-check-url https://target.com/account --auth-check-text "attacker-name"
```

Every candidate endpoint gets three requests under three identities:

1. **Victim B** requests their own object and is served it — so the object exists, is private, and B owns it.
2. An **unauthenticated** client requests the same URL and is refused — so it is not simply public, by far the most common false positive.
3. **Attacker A**, a different logged-in account, requests it and is served B's data anyway.

All three must hold. If the anonymous request succeeds, the resource is public
and nothing is reported. If Attacker A gets 401/403/404, or their own data
rather than B's, nothing is reported. SmartHunt also re-requests with a
different object ID: identical responses mean the endpoint ignores the
identifier and is returning a generic page, not B's record.

**Both accounts must be yours.** SmartHunt only ever reads objects Account B has
itself confirmed it owns, and every request is a read.

---

## OWASP Top 10 coverage

A dedicated stage tests the discovered attack surface across all ten 2021
categories. Every check is **non-destructive** — bounded GET-style probes, no
payload that writes, deletes or degrades the target.

| | Category | What is actually tested |
|---|---|---|
| A01 | Broken Access Control | **IDOR with two sessions**, path traversal, open redirect |
| A02 | Cryptographic Failures | Secrets in JS bundles, transport checks |
| A03 | Injection | SQL injection (5 engines), reflected XSS, SSTI, CRLF |
| A04 | Insecure Design | Rate-limit and workflow probes |
| A05 | Security Misconfiguration | Credentialed CORS reflection, risky methods, exposed `.env` / `.git` / actuator |
| A06 | Vulnerable Components | Version banners matched against known CVEs |
| A07 | Auth Failures | JWT exposure, session attributes |
| A08 | Integrity Failures | Third-party scripts without Subresource Integrity |
| A09 | Logging Failures | Stack traces and verbose errors leaking internals |
| A10 | SSRF | URL-taking parameters; `--collaborator` to prove the callback |

Two categories are honest about their limits: **SSRF** cannot be proven without a
collaborator host you control, and **A09** is not externally observable. Both are
recorded as candidates rather than dressed up as findings.

```bash
python smarthunt.py --cli example.com --collaborator abc123.oast.fun
```

---

## Known-CVE matching

Every fingerprinted banner and library version is matched against a curated
table of high-signal, remotely-checkable CVEs — Apache path traversal, Ghostcat,
Spring4Shell, ProxyShell, Drupalgeddon, Heartbleed, jQuery XSS and prototype
pollution. `--cve-online` additionally queries OSV and NVD.

**These are never reported as findings.** A version banner proves nothing:
banners lie, distributions backport fixes without bumping the string, and the
vulnerable code path may not even be reachable. Every match is labelled
inference, carries low confidence, has an empty impact field, and is refused by
the triage gate. What each one carries instead is the safe check that confirms
or kills it by hand:

```
[critical] target.com: CVE-2021-41773 — Apache path traversal (2.4.49)
           NOT verified — GET /cgi-bin/.%2e/%2e%2e/etc/passwd confirms it
```

---

## Wildcard goes deep on every subdomain

Finding subdomains is the easy half. In wildcard mode SmartHunt runs the *whole*
domain-mode pipeline against everything it found alive — pulling each host's
JavaScript, mining it for endpoints, then **verifying those endpoints host by
host**.

That last step matters. Reading a bundle gives you path strings; `/api/v2/billing`
is a guess until something answers it. SmartHunt joins every mined path onto
every live host and probes it, because staging subdomains routinely expose an
API that production does not. What comes back — with status, content type and
allowed methods — is the real, callable attack surface, and it feeds straight
into the OWASP and access-control stages.

---

## Exhaustive mode — nothing left behind

```bash
python smarthunt.py --cli '*.example.com' --exhaustive     # or -E
python smarthunt.py --cli example.com -E --rounds 6
```

A normal scan has caps that keep it quick. `--exhaustive` raises them and turns
discovery into a **loop that runs until a round finds nothing new**.

Each round's discoveries seed the next. A subdomain found by permutation hosts
JavaScript naming a second subdomain, whose bundle names an API on a third — a
single pass stops at the first hop. Every round re-mines three sources:
hostnames embedded in collected URLs, hostnames referenced inside JavaScript,
and a fresh permutation pass seeded by what *this scan* has actually seen.

```
▶ Exhaustive round 2/3
  round 2: hosts 1->53, URLs 170->814, live 1->52
▶ Exhaustive round 3/3
  round 3: hosts 53->53, URLs 814->814, live 52->52
  converged after 3 rounds — nothing new to find
```

The ceilings go up rather than away, and `--rounds` bounds the loop, because an
unbounded crawl over a large wildcard scope never terminates — which is not the
same thing as thorough.

**Wildcard DNS is detected first.** Many domains answer *every* name, so
bruteforce and permutation would otherwise "find" thousands of hosts that do not
exist — and in exhaustive mode that becomes an endless supply. SmartHunt queries
names nobody would register, learns the wildcard's addresses, and drops any
guessed host that only resolves there. Hosts from passive sources are kept,
because something attested to those.

---

## The arsenal — 112 tools, all driven

![Arsenal panel](docs/arsenal.png)

Where tools find *different* things, SmartHunt runs them all and merges: every
subdomain source, all permutation generators, both takeover scanners, every JS
analyser (jsluice, LinkFinder, SecretFinder, xnLinkFinder, mantra, trufflehog,
gitleaks), every content fuzzer.

Where tools are interchangeable implementations of the same scan — port
scanners, DNS resolvers — the best available one runs, because three tools
repeating one scan is just three times the traffic. `sqlmap` is the exception
that proves the rule: it only runs against a parameter whose database error has
already been captured, turning a proven injection into a confirmed one instead
of hammering every parameter on the site.

Categories: subdomain enumeration and permutation, DNS, HTTP probing, port
scanning, OSINT/attack surface, crawling, JavaScript analysis, parameter
discovery, content discovery, API & GraphQL, vulnerability scanning, injection
testing, takeover, cloud storage, TLS, CMS scanning, out-of-band, screenshots
and secret scanning.

Adding a tool is one row in `smarthunt/extra_tools.py`.

---

## Interface

Both front-ends share one engine, one palette and one feature set — a phosphor
terminal skin with matrix rain, a boot sequence, count-up readouts, a spinner on
the running stage and a glitch when a finding lands. All motion respects
`prefers-reduced-motion`.

![SmartHunt desktop app](docs/screenshot.png)

The browser UI, held still:

![SmartHunt browser UI](docs/web-ui.png)

The browser UI runs on Python's stdlib `http.server`, so it needs no extra
dependency. Because it lives on an origin every page in your browser can reach,
it defends itself on three fronts: `Host` must be a loopback name (blocking DNS
rebinding), every mutating request must carry a per-process `X-SmartHunt-Token`
stamped into the page, and a cross-origin `Origin` is rejected. Without that
token check, any site you happened to be visiting could quietly start scans from
your machine.

On a remote box, don't expose the port — forward it:

```bash
ssh -L 8777:127.0.0.1:8777 you@your-vps    # then browse http://127.0.0.1:8777
```

---

## The pipeline

| # | Stage | What it does |
|---|---|---|
| 1 | Subdomain Enumeration | Every passive source and installed tool, plus DNS bruteforce and permutation (wildcard mode) |
| 2 | DNS Resolution | Resolves hosts to IPs and CNAMEs; detects wildcard DNS |
| 3 | Port Scanning | Top ports or your own list |
| 4 | HTTP Probing | Finds live web services, status, title, server |
| 5 | Technology Fingerprinting | Headers, cookies, body markers |
| 6 | Subdomain Takeover | Dangling CNAMEs against 25+ provider fingerprints |
| 7 | URL / Endpoint Collection | Archives, crawlers, and a built-in crawler |
| 8 | JavaScript Gathering & Analysis | Pulls every JS file; mines endpoints, parameters, secrets |
| 9 | API Endpoint Verification | Probes mined paths against every live host; keeps what answers |
| 10 | Parameter Discovery | Names and values from URLs, tools and the corpus |
| 11 | Content Discovery | Curated paths plus your wordlist |
| 12 | Vulnerability Checks | Exposed files, headers, transport, nuclei |
| 13 | OWASP Top 10 Testing | Active non-destructive checks across all ten categories |
| 14 | Known CVE Matching | Version-inferred CVEs, flagged for manual confirmation |
| 15 | Access Control / IDOR | Attacker A vs Victim B (needs two sessions) |
| 16 | Screenshots | Visual triage of live hosts |
| — | **Triage** | Evidence gate → the single reportable finding |

---

## Results

Every scan exports:

```
smarthunt-results/example_com/
├── example_com.json          # everything, including the triaged report
├── example_com.html          # standalone HTML report
├── example_com.md            # Markdown, ready to paste into a submission
├── example_com-findings.csv
└── lists/
    ├── subdomains.txt  live-hosts.txt  urls.txt
    ├── js-files.txt    endpoints.txt   parameters.txt
```

---

## Options

```bash
python smarthunt.py --help
```

| Flag | Purpose |
|---|---|
| `--web` / `--port` / `--open` | Browser UI |
| `--cli` / `-y` | Headless, skip the authorization prompt |
| `--exhaustive` / `-E` / `--rounds` | Loop discovery until nothing new appears |
| `--auth-cookie` / `--auth-bearer` / `--auth-headers` | Session for Account A |
| `--auth-check-url` / `--auth-check-text` | Prove the session is live |
| `--victim-cookie` / `--victim-bearer` / `--victim-headers` | Account B, enables IDOR |
| `--collaborator` | Host that observes SSRF callbacks |
| `--cve-online` | Also query OSV and NVD |
| `--no-sqlmap` | Skip sqlmap confirmation on proven injection points |
| `--threads` / `--depth` / `--max-pages` / `--max-js` | Tuning |
| `--stages` / `--all` | Pick modules explicitly |
| `--sub-wordlist` / `--content-wordlist` | Your own wordlists |
| `--tools` | Show which of the 112 tools were detected |

---

## Authorization

SmartHunt sends real, active traffic. Both UIs require you to confirm
authorization before a scan starts, and the CLI needs `-y`.

**Only scan targets you own or have written permission to test** — an in-scope
bug bounty program, a client engagement with a signed statement of work, or your
own infrastructure. Check the program's rules before running authenticated or
automated testing; some restrict both, and a session makes the traffic
attributable to your account.

The access-control checks require two accounts **you control**. They only read
objects Account B has itself confirmed it owns, and never touch real users' data.

---

## Requirements

- Python 3.9+
- `requests` (the only dependency)
- Tkinter for the desktop app — optional, `--web` and `--cli` work without it
- Any of the 112 external tools you care to install — all optional
