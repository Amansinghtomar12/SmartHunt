# SmartHunt

A GUI bug-hunting recon suite. Point it at a domain, press **START**, and it runs a
full reconnaissance pipeline — subdomain enumeration, HTTP probing, JavaScript
gathering, endpoint and parameter discovery, secret hunting, content discovery and
vulnerability checks — then hands you sortable results and an exportable report.

![SmartHunt](docs/screenshot.png)

---

## Two target modes

The target box gives you exactly two options, and they run different pipelines:

| Mode | Input | What it does |
|---|---|---|
| **Single Domain** | `example.com` | Deep-dive one host. Crawls it, pulls **every JavaScript file** it can reach, mines those files for endpoints, parameters and hardcoded secrets, then discovers content and tests what it found. |
| **Wildcard** | `*.example.com` | Goes wide first. Runs **every** subdomain source and tool available, resolves them, probes for live web services, port-scans, checks for subdomain takeover — then runs the full deep-dive on everything that came back alive. |

Typing `*.example.com` into the box switches to wildcard mode automatically.

---

## Quick start

```bash
git clone <this repo>
cd SmartHunt
pip install -r requirements.txt      # just `requests`
python smarthunt.py                  # launch the GUI
```

That's it. **No external tools are required** — SmartHunt ships pure-Python
implementations of every stage. Installing the optional tools below makes it
faster and deeper, but it produces real results out of the box.

If Tkinter is missing:

```bash
sudo apt install python3-tk       # Debian / Ubuntu
sudo dnf install python3-tkinter  # Fedora / RHEL
brew install python-tk            # macOS
```

### Other ways to launch

```bash
python smarthunt.py example.com               # GUI with the target pre-filled
python smarthunt.py --tools                   # show which external tools were found
python smarthunt.py --cli example.com         # headless, same engine
python smarthunt.py --cli '*.example.com' --all --out results/
python -m smarthunt                           # GUI via the package
```

---

## Hybrid engine

Every stage prefers a real external tool when one is on your `PATH`, and falls
back to a built-in pure-Python implementation when it isn't. The **Arsenal** tab
shows what was detected and the exact install command for everything missing.

**52 tools are wired in:**

| Category | Tools |
|---|---|
| Subdomain enumeration | `subfinder` `assetfinder` `amass` `findomain` `chaos` `github-subdomains` `shosubgo` |
| Permutation / brute force | `dnsgen` `gotator` `altdns` `puredns` `shuffledns` `massdns` |
| DNS resolution | `dnsx` |
| HTTP probing | `httpx` `httprobe` |
| Port scanning | `naabu` `nmap` `masscan` |
| Crawling / URLs | `katana` `gau` `waybackurls` `hakrawler` `gospider` `urlfinder` |
| JavaScript analysis | `subjs` `getJS` `jsluice` `linkfinder` `secretfinder` `xnLinkFinder` `mantra` |
| Parameter discovery | `paramspider` `arjun` `unfurl` `qsreplace` |
| Content discovery | `ffuf` `feroxbuster` `dirsearch` `kiterunner` |
| Vulnerability scanning | `nuclei` `dalfox` `crlfuzz` `sqlmap` `corsy` `smuggler` |
| Subdomain takeover | `subzy` `subjack` |
| Screenshots | `gowitness` `aquatone` |
| Secret scanning | `trufflehog` `gitleaks` |

Install the common set with:

```bash
./install-tools.sh          # needs Go; installs the Go-based tools
./install-tools.sh --all    # also installs the pip/apt ones
```

### Built-in fallbacks (no tools needed)

Even with nothing installed, SmartHunt still queries these **passive sources directly**:

- **Subdomains** — crt.sh, CertSpotter, HackerTarget, AlienVault OTX, RapidDNS,
  Anubis, urlscan.io, Wayback Machine (+ VirusTotal, SecurityTrails and Shodan
  when their API keys are set)
- **URLs** — Wayback Machine, AlienVault OTX, Common Crawl, urlscan.io

plus a threaded DNS bruteforcer, TCP connect port scanner, HTTP prober, breadth-first
crawler, technology fingerprinter, JavaScript endpoint/secret extractor, content
discovery engine, CNAME takeover fingerprinter and passive misconfiguration checks.

Optional API keys (set as environment variables): `VT_API_KEY`,
`SECURITYTRAILS_API_KEY`, `SHODAN_API_KEY`.

---

## The pipeline

Modules can be toggled individually in the sidebar. Ones that don't apply to the
current mode are greyed out.

| # | Module | Domain | Wildcard | What it does |
|---|---|:---:|:---:|---|
| 1 | Subdomain Enumeration | — | ✓ | All tools + all passive sources + bruteforce + permutation |
| 2 | DNS Resolution | ✓ | ✓ | A records and CNAMEs |
| 3 | Port Scanning | ✓ | ✓ | Top ports, or a custom list |
| 4 | HTTP Probing | ✓ | ✓ | Status, title, server, content length |
| 5 | Technology Fingerprinting | ✓ | ✓ | Headers, cookies and body signatures |
| 6 | Subdomain Takeover | — | ✓ | 27 dangling-CNAME service fingerprints |
| 7 | URL / Endpoint Collection | ✓ | ✓ | Archives + external crawlers + built-in crawler |
| 8 | JavaScript Gathering & Analysis | ✓ | ✓ | Collect every JS file, mine endpoints/params/secrets |
| 9 | Parameter Discovery | ✓ | ✓ | Parameter names and observed values |
| 10 | Content Discovery | ✓ | ✓ | Sensitive paths, admin panels, backups, configs |
| 11 | Vulnerability Checks | ✓ | ✓ | nuclei/dalfox/crlfuzz + always-on passive checks |
| 12 | Screenshots | ✓ | ✓ | Visual triage of live hosts |

### JavaScript analysis

This is the core of domain mode. SmartHunt collects JS from `<script src>` tags,
inline references, archive results and `subjs`/`getJS`, downloads each file, and
extracts:

- **Endpoints** — using the LinkFinder regex plus path/URL patterns, scoped to your target
- **Parameters** — query keys referenced anywhere in the code
- **Secrets** — 26 credential patterns: AWS keys, Google/Firebase API keys, GitHub
  and GitLab tokens, Stripe live keys, Slack tokens and webhooks, SendGrid,
  Mailgun, Mailchimp, Twilio, Heroku, JWTs, private key blocks, basic-auth URLs,
  internal hostnames, S3 buckets and generic API-key/password assignments

Placeholder values (`YOUR_API_KEY_HERE`, `xxxxxx`, `changeme`) are filtered out so
the Secrets tab stays signal.

---

## Results

Eleven result tabs, all filterable and sortable, with copy-to-clipboard and
double-click-to-open:

**Dashboard** · **Findings** · **Secrets** · **Hosts** · **Subdomains** · **URLs** ·
**JS** · **Endpoints** · **Params** · **Content** · **Log** · **Arsenal**

**Export all** writes:

```
smarthunt-results/example_com/
├── example_com.json           full structured results
├── example_com.html           standalone report, opens in any browser
├── example_com.md             Markdown summary
├── example_com-findings.csv   findings for a spreadsheet
└── lists/
    ├── subdomains.txt         ready to pipe into other tools
    ├── live-hosts.txt
    ├── urls.txt
    ├── js-files.txt
    ├── endpoints.txt
    └── parameters.txt
```

---

## Options

| Option | Default | Notes |
|---|---|---|
| Threads | 40 | Raise for speed, lower to be gentle on the target |
| Crawl depth | 2 | Built-in and external crawlers |
| Max pages to crawl | 300 | Caps the built-in crawler |
| Max JS files | 400 | Caps JS downloads |
| Ports | built-in top ~50 | Or a custom list like `80,443,8080` |
| nuclei severity | `low,medium,high,critical` | Passed straight to nuclei |
| DNS bruteforce | on | Disable for passive-only recon |
| Wordlists | built-in | Point at SecLists for real coverage |

Controls: **START**, **STOP** (finishes the current module then halts) and
**pause/resume** at module boundaries.

---

## Authorization

SmartHunt sends live traffic to whatever you point it at, and asks you to confirm
authorization before every scan.

**Only scan targets you own or have written permission to test** — your own
infrastructure, or a target explicitly in scope for a bug bounty program you have
joined. Check the program's scope and rules first; many prohibit automated
scanning or rate-limit it. Unauthorized scanning is illegal in most jurisdictions.

The defaults are deliberately moderate. If a program caps request rates, lower the
thread count and disable bruteforce and content discovery.

---

## Requirements

- Python 3.9+
- `requests` (`pip install -r requirements.txt`)
- Tkinter (bundled with most Python installs; see above if missing)

Everything else is optional.
