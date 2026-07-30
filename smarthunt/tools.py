"""Registry, detection and execution of external recon tools.

SmartHunt runs in *hybrid* mode.  Every stage prefers a real, battle-tested
external binary when one is on ``PATH`` and otherwise falls back to a
pure-Python implementation, so a fresh clone still produces results with zero
setup.

:data:`REGISTRY` is the catalogue of every tool SmartHunt knows how to drive.
The GUI renders it as an "Arsenal" panel showing what is installed, what is
missing, and the exact command to install each one.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field

# Category constants (also the order they appear in the GUI arsenal panel)
CAT_SUBDOMAIN = "Subdomain Enumeration"
CAT_PERMUTE = "Subdomain Permutation"
CAT_RESOLVE = "DNS Resolution"
CAT_PROBE = "HTTP Probing"
CAT_PORTS = "Port Scanning"
CAT_CRAWL = "Crawling / URL Collection"
CAT_JS = "JavaScript Analysis"
CAT_PARAMS = "Parameter Discovery"
CAT_CONTENT = "Content Discovery"
CAT_VULN = "Vulnerability Scanning"
CAT_TAKEOVER = "Subdomain Takeover"
CAT_SCREENSHOT = "Screenshots"
CAT_SECRETS = "Secret Scanning"
CAT_OSINT = "OSINT / Attack Surface"
CAT_API = "API & GraphQL"
CAT_INJECT = "Injection Testing"
CAT_TLS = "TLS / Transport"
CAT_CMS = "CMS & Server Scanning"
CAT_CLOUD = "Cloud & Storage"
CAT_OOB = "Out-of-Band"

CATEGORIES = [
    CAT_SUBDOMAIN, CAT_PERMUTE, CAT_RESOLVE, CAT_PROBE, CAT_PORTS, CAT_OSINT,
    CAT_CRAWL, CAT_JS, CAT_PARAMS, CAT_CONTENT, CAT_API, CAT_VULN, CAT_INJECT,
    CAT_TAKEOVER, CAT_CLOUD, CAT_TLS, CAT_CMS, CAT_OOB, CAT_SCREENSHOT,
    CAT_SECRETS,
]


@dataclass(frozen=True)
class Tool:
    """A single external tool SmartHunt can drive."""

    name: str
    category: str
    description: str
    install: str
    modes: tuple[str, ...] = ("domain", "wildcard")  # which scan modes use it


def _t(name, category, description, install, modes=("domain", "wildcard")) -> Tool:
    return Tool(name, category, description, install, modes)


GO = "go install -v github.com/"

#: Everything SmartHunt knows how to use.  Ordered by category for display.
REGISTRY: tuple[Tool, ...] = (
    # --- Subdomain enumeration (wildcard mode) -----------------------------
    _t("subfinder", CAT_SUBDOMAIN, "Fast passive subdomain discovery across 30+ sources",
       f"{GO}projectdiscovery/subfinder/v2/cmd/subfinder@latest", ("wildcard",)),
    _t("assetfinder", CAT_SUBDOMAIN, "Finds domains and subdomains related to a target",
       f"{GO}tomnomnom/assetfinder@latest", ("wildcard",)),
    _t("amass", CAT_SUBDOMAIN, "In-depth attack-surface mapping and asset discovery",
       f"{GO}owasp-amass/amass/v4/...@master", ("wildcard",)),
    _t("findomain", CAT_SUBDOMAIN, "Cross-platform subdomain enumerator",
       "https://github.com/Findomain/Findomain/releases", ("wildcard",)),
    _t("chaos", CAT_SUBDOMAIN, "Queries the ProjectDiscovery Chaos subdomain dataset",
       f"{GO}projectdiscovery/chaos-client/cmd/chaos@latest", ("wildcard",)),
    _t("github-subdomains", CAT_SUBDOMAIN, "Mines GitHub code search for subdomains",
       f"{GO}gwen001/github-subdomains@latest", ("wildcard",)),
    _t("shosubgo", CAT_SUBDOMAIN, "Pulls subdomains from the Shodan API",
       f"{GO}incogbyte/shosubgo@latest", ("wildcard",)),

    # --- Permutation / brute force -----------------------------------------
    _t("dnsgen", CAT_PERMUTE, "Generates permutations of known subdomains",
       "pipx install dnsgen", ("wildcard",)),
    _t("gotator", CAT_PERMUTE, "DNS wordlist permutation generator",
       f"{GO}Josue87/gotator@latest", ("wildcard",)),
    _t("altdns", CAT_PERMUTE, "Alteration/permutation subdomain discovery",
       "pipx install py-altdns", ("wildcard",)),
    _t("puredns", CAT_PERMUTE, "Fast domain bruteforce with wildcard filtering",
       f"{GO}d3mondev/puredns/v2@latest", ("wildcard",)),
    _t("shuffledns", CAT_PERMUTE, "massdns wrapper for bruteforce + wildcard handling",
       f"{GO}projectdiscovery/shuffledns/cmd/shuffledns@latest", ("wildcard",)),
    _t("massdns", CAT_PERMUTE, "High-performance DNS stub resolver",
       "https://github.com/blechschmidt/massdns", ("wildcard",)),

    # --- Resolution ---------------------------------------------------------
    _t("dnsx", CAT_RESOLVE, "Fast and multi-purpose DNS toolkit",
       f"{GO}projectdiscovery/dnsx/cmd/dnsx@latest"),

    # --- HTTP probing -------------------------------------------------------
    _t("httpx", CAT_PROBE, "Fast HTTP prober: status, title, tech, CDN, TLS",
       f"{GO}projectdiscovery/httpx/cmd/httpx@latest"),
    _t("httprobe", CAT_PROBE, "Simple concurrent http/https prober",
       f"{GO}tomnomnom/httprobe@latest"),

    # --- Port scanning ------------------------------------------------------
    _t("naabu", CAT_PORTS, "Fast SYN/CONNECT port scanner",
       f"{GO}projectdiscovery/naabu/v2/cmd/naabu@latest"),
    _t("nmap", CAT_PORTS, "Service/version detection and NSE scripting",
       "apt install nmap  |  brew install nmap"),
    _t("masscan", CAT_PORTS, "Internet-scale asynchronous port scanner",
       "apt install masscan"),

    # --- Crawling / URL collection -----------------------------------------
    _t("katana", CAT_CRAWL, "Next-gen crawler with headless + JS parsing",
       f"{GO}projectdiscovery/katana/cmd/katana@latest"),
    _t("gau", CAT_CRAWL, "Fetches known URLs from Wayback, OTX, URLScan, CommonCrawl",
       f"{GO}lc/gau/v2/cmd/gau@latest"),
    _t("waybackurls", CAT_CRAWL, "Fetches all URLs the Wayback Machine knows",
       f"{GO}tomnomnom/waybackurls@latest"),
    _t("hakrawler", CAT_CRAWL, "Fast web crawler for endpoint discovery",
       f"{GO}hakluke/hakrawler@latest"),
    _t("gospider", CAT_CRAWL, "Fast web spider with JS link extraction",
       f"{GO}jaeles-project/gospider@latest"),
    _t("urlfinder", CAT_CRAWL, "Passive URL discovery across archive sources",
       f"{GO}projectdiscovery/urlfinder/cmd/urlfinder@latest"),

    # --- JavaScript analysis (domain mode focus) ---------------------------
    _t("subjs", CAT_JS, "Extracts JavaScript file URLs from a list of hosts",
       f"{GO}lc/subjs@latest", ("domain", "wildcard")),
    _t("getJS", CAT_JS, "Pulls all JavaScript sources referenced by a page",
       f"{GO}003random/getJS@latest"),
    _t("jsluice", CAT_JS, "Extracts URLs, paths, secrets and gadgets from JavaScript",
       f"{GO}BishopFox/jsluice/cmd/jsluice@latest"),
    _t("linkfinder", CAT_JS, "Regex endpoint extraction from JS files",
       "https://github.com/GerbenJavado/LinkFinder"),
    _t("secretfinder", CAT_JS, "Finds API keys and secrets inside JS files",
       "https://github.com/m4ll0k/SecretFinder"),
    _t("xnLinkFinder", CAT_JS, "Deep endpoint/parameter discovery from JS and traffic",
       "pipx install xnLinkFinder"),
    _t("mantra", CAT_JS, "Hunts hardcoded API keys in JS files",
       f"{GO}MrEmpy/mantra@latest"),

    # --- Parameter discovery -----------------------------------------------
    _t("paramspider", CAT_PARAMS, "Mines parameter names from web archives",
       "pipx install paramspider"),
    _t("arjun", CAT_PARAMS, "HTTP parameter discovery suite",
       "pipx install arjun"),
    _t("unfurl", CAT_PARAMS, "Pulls apart URLs to extract keys, paths and domains",
       f"{GO}tomnomnom/unfurl@latest"),
    _t("qsreplace", CAT_PARAMS, "Replaces query-string values for payload injection",
       f"{GO}tomnomnom/qsreplace@latest"),

    # --- Content discovery --------------------------------------------------
    _t("ffuf", CAT_CONTENT, "Fast web fuzzer for directories, files and vhosts",
       f"{GO}ffuf/ffuf/v2@latest"),
    _t("feroxbuster", CAT_CONTENT, "Recursive content discovery in Rust",
       "https://github.com/epi052/feroxbuster"),
    _t("dirsearch", CAT_CONTENT, "Web path scanner",
       "pipx install dirsearch"),
    _t("kiterunner", CAT_CONTENT, "API endpoint discovery using route wordlists",
       "https://github.com/assetnote/kiterunner"),

    # --- Vulnerability scanning --------------------------------------------
    _t("nuclei", CAT_VULN, "Template-driven vulnerability scanner",
       f"{GO}projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    _t("dalfox", CAT_VULN, "Parameter analysis and XSS scanner",
       f"{GO}hahwul/dalfox/v2@latest"),
    _t("crlfuzz", CAT_VULN, "CRLF injection scanner",
       f"{GO}dwisiswant0/crlfuzz/cmd/crlfuzz@latest"),
    _t("sqlmap", CAT_VULN, "Automatic SQL injection detection and exploitation",
       "pipx install sqlmap"),
    _t("corsy", CAT_VULN, "CORS misconfiguration scanner",
       "https://github.com/s0md3v/Corsy"),
    _t("smuggler", CAT_VULN, "HTTP request smuggling detection",
       "https://github.com/defparam/smuggler"),

    # --- Subdomain takeover -------------------------------------------------
    _t("subzy", CAT_TAKEOVER, "Subdomain takeover vulnerability checker",
       f"{GO}PentestPad/subzy@latest", ("wildcard",)),
    _t("subjack", CAT_TAKEOVER, "Subdomain takeover scanner",
       f"{GO}haccer/subjack@latest", ("wildcard",)),

    # --- Screenshots --------------------------------------------------------
    _t("gowitness", CAT_SCREENSHOT, "Headless-Chrome web screenshot utility",
       f"{GO}sensepost/gowitness@latest"),
    _t("aquatone", CAT_SCREENSHOT, "Visual inspection of websites across hosts",
       "https://github.com/michenriksen/aquatone"),

    # --- Secret scanning ----------------------------------------------------
    _t("trufflehog", CAT_SECRETS, "Verified credential detection in code and JS",
       f"{GO}trufflesecurity/trufflehog/v3@latest"),
    _t("gitleaks", CAT_SECRETS, "Secret detection in git repos and files",
       f"{GO}gitleaks/gitleaks/v8@latest"),
    _t("noseyparker", CAT_SECRETS, "High-signal secret detection with dedup",
       "https://github.com/praetorian-inc/noseyparker/releases"),
    _t("ripsecrets", CAT_SECRETS, "Fast pre-commit style secret scanner",
       "cargo install ripsecrets"),

    # --- Extra subdomain sources -------------------------------------------
    _t("sublist3r", CAT_SUBDOMAIN, "Classic multi-engine subdomain enumerator",
       "pipx install sublist3r"),
    _t("knockpy", CAT_SUBDOMAIN, "Subdomain scanner with wordlist and API sources",
       "pipx install knock-subdomains"),
    _t("crobat", CAT_SUBDOMAIN, "Queries the Rapid7 Sonar dataset",
       f"{GO}cgboal/sonarsearch/cmd/crobat@latest"),
    _t("haktrails", CAT_SUBDOMAIN, "SecurityTrails subdomains and DNS history",
       f"{GO}hakluke/haktrails@latest"),
    _t("cero", CAT_SUBDOMAIN, "Scrapes domain names from TLS certificates",
       f"{GO}glebarez/cero@latest"),
    _t("subfinder-recursive", CAT_SUBDOMAIN, "Recursive subfinder pass over found hosts",
       f"{GO}projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    _t("alterx", CAT_PERMUTE, "Pattern-based subdomain permutation generator",
       f"{GO}projectdiscovery/alterx/cmd/alterx@latest"),
    _t("ripgen", CAT_PERMUTE, "Rust permutation generator, very fast",
       "cargo install ripgen"),

    # --- OSINT / attack surface --------------------------------------------
    _t("asnmap", CAT_OSINT, "Maps an organisation's ASN to its IP ranges",
       f"{GO}projectdiscovery/asnmap/cmd/asnmap@latest"),
    _t("mapcidr", CAT_OSINT, "Expands and manipulates CIDR ranges",
       f"{GO}projectdiscovery/mapcidr/cmd/mapcidr@latest"),
    _t("cdncheck", CAT_OSINT, "Flags which hosts sit behind a CDN or WAF",
       f"{GO}projectdiscovery/cdncheck/cmd/cdncheck@latest"),
    _t("uncover", CAT_OSINT, "Pivots through Shodan, Censys, Fofa and ZoomEye",
       f"{GO}projectdiscovery/uncover/cmd/uncover@latest"),
    _t("tlsx", CAT_OSINT, "TLS grabber: SANs, issuers, expiry, JARM",
       f"{GO}projectdiscovery/tlsx/cmd/tlsx@latest"),
    _t("hakip2host", CAT_OSINT, "Turns IP ranges back into hostnames",
       f"{GO}hakluke/hakip2host@latest"),
    _t("dnsvalidator", CAT_OSINT, "Builds a clean, working resolver list",
       "pipx install dnsvalidator"),
    _t("gitdorker", CAT_OSINT, "GitHub dorking for leaked target data",
       "https://github.com/obheda12/GitDorker"),

    # --- More crawling ------------------------------------------------------
    _t("waymore", CAT_CRAWL, "Deep archive pull: Wayback, CommonCrawl, AlienVault, URLScan",
       "pipx install waymore"),
    _t("gauplus", CAT_CRAWL, "Faster gau fork with more sources",
       f"{GO}bp0lr/gauplus@latest"),
    _t("xurlfind3r", CAT_CRAWL, "Passive URL discovery across many archives",
       f"{GO}hueristiq/xurlfind3r/cmd/xurlfind3r@latest"),
    _t("photon", CAT_CRAWL, "OSINT crawler that extracts intel while spidering",
       "https://github.com/s0md3v/Photon"),
    _t("cariddi", CAT_CRAWL, "Crawls for endpoints, secrets, tokens and errors",
       f"{GO}edoardottt/cariddi/cmd/cariddi@latest"),

    # --- More JS ------------------------------------------------------------
    _t("jsleak", CAT_JS, "Finds links and secrets inside JavaScript",
       f"{GO}channyein1337/jsleak@latest"),
    _t("jsubfinder", CAT_JS, "Digs subdomains and secrets out of JS files",
       f"{GO}ThreatUnkown/jsubfinder@latest"),
    _t("sourcemapper", CAT_JS, "Reconstructs original source from .js.map files",
       f"{GO}denandz/sourcemapper@latest"),

    # --- More parameter discovery ------------------------------------------
    _t("x8", CAT_PARAMS, "Hidden parameter discovery by response diffing",
       "cargo install x8"),
    _t("parameth", CAT_PARAMS, "Brute-forces GET and POST parameters",
       "https://github.com/maK-/parameth"),

    # --- More content discovery --------------------------------------------
    _t("gobuster", CAT_CONTENT, "Directory, DNS and vhost brute-forcing",
       f"{GO}OJ/gobuster/v3@latest"),
    _t("wfuzz", CAT_CONTENT, "Highly configurable web fuzzer",
       "pipx install wfuzz"),
    _t("dirb", CAT_CONTENT, "Classic dictionary-based content scanner",
       "apt install dirb"),

    # --- API & GraphQL ------------------------------------------------------
    _t("graphw00f", CAT_API, "Fingerprints the GraphQL engine in use",
       "https://github.com/dolevf/graphw00f"),
    _t("clairvoyance", CAT_API, "Recovers a GraphQL schema when introspection is off",
       "pipx install clairvoyance"),
    _t("inql", CAT_API, "GraphQL introspection and query generation",
       "pipx install inql"),
    _t("swagger-cli", CAT_API, "Validates and dereferences OpenAPI specs",
       "npm install -g @apidevtools/swagger-cli"),
    _t("jwt_tool", CAT_API, "JWT analysis: alg confusion, weak keys, claim tampering",
       "https://github.com/ticarpi/jwt_tool"),

    # --- Injection testing --------------------------------------------------
    _t("ghauri", CAT_INJECT, "Modern SQL injection detection and exploitation",
       "pipx install ghauri"),
    _t("XSStrike", CAT_INJECT, "XSS scanner with context analysis and WAF fingerprinting",
       "https://github.com/s0md3v/XSStrike"),
    _t("kxss", CAT_INJECT, "Finds parameters that reflect XSS-relevant characters",
       f"{GO}Emoe/kxss@latest"),
    _t("Gxss", CAT_INJECT, "Checks which parameters reflect into the response",
       f"{GO}KathanP19/Gxss@latest"),
    _t("commix", CAT_INJECT, "Command injection detection and exploitation",
       "https://github.com/commixproject/commix"),
    _t("tplmap", CAT_INJECT, "Server-side template injection exploitation",
       "https://github.com/epinna/tplmap"),
    _t("SSRFmap", CAT_INJECT, "SSRF exploitation with an internal-service module set",
       "https://github.com/swisskyrepo/SSRFmap"),
    _t("ppfuzz", CAT_INJECT, "Client-side prototype pollution fuzzer",
       "cargo install ppfuzz"),
    _t("bxss", CAT_INJECT, "Blind XSS injection across parameters and headers",
       f"{GO}ethicalhackingplayground/bxss@latest"),
    _t("jaeles", CAT_VULN, "Signature-based web vulnerability scanner",
       f"{GO}jaeles-project/jaeles@latest"),
    _t("nikto", CAT_CMS, "Classic web server misconfiguration scanner",
       "apt install nikto"),
    _t("wpscan", CAT_CMS, "WordPress core, plugin and theme vulnerability scanner",
       "gem install wpscan"),
    _t("joomscan", CAT_CMS, "Joomla vulnerability scanner",
       "https://github.com/OWASP/joomscan"),
    _t("droopescan", CAT_CMS, "Drupal, SilverStripe and Joomla scanner",
       "pipx install droopescan"),

    # --- TLS / transport ----------------------------------------------------
    _t("testssl.sh", CAT_TLS, "Thorough TLS configuration and cipher audit",
       "https://github.com/drwetter/testssl.sh"),
    _t("sslyze", CAT_TLS, "Fast TLS scanner with structured JSON output",
       "pipx install sslyze"),

    # --- Cloud & storage ----------------------------------------------------
    _t("s3scanner", CAT_CLOUD, "Finds and tests open S3 buckets",
       f"{GO}sa7mon/s3scanner@latest"),
    _t("cloud_enum", CAT_CLOUD, "Enumerates public AWS, Azure and GCP assets",
       "https://github.com/initstring/cloud_enum"),
    _t("dnsReaper", CAT_TAKEOVER, "Subdomain takeover scanner with 50+ signatures",
       "https://github.com/punk-security/dnsReaper"),
    _t("tko-subs", CAT_TAKEOVER, "Takeover detection driven by a CNAME provider list",
       f"{GO}anshumanbh/tko-subs@latest"),

    # --- Out-of-band --------------------------------------------------------
    _t("interactsh-client", CAT_OOB, "OOB interaction server for blind SSRF/RCE/XXE proof",
       f"{GO}projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    _t("notify", CAT_OOB, "Streams findings to Slack, Discord or Telegram",
       f"{GO}projectdiscovery/notify/cmd/notify@latest"),

    # --- Extra port scanning ------------------------------------------------
    _t("rustscan", CAT_PORTS, "Very fast port sweep that hands off to nmap",
       "cargo install rustscan"),
    _t("smap", CAT_PORTS, "Passive nmap-style results via Shodan, no packets sent",
       f"{GO}s0md3v/smap/cmd/smap@latest"),
)

BY_NAME: dict[str, Tool] = {t.name: t for t in REGISTRY}


@dataclass
class ToolInventory:
    """A snapshot of which registry tools are installed on this machine."""

    available: dict[str, str] = field(default_factory=dict)  # name -> resolved path

    def has(self, name: str) -> bool:
        return name in self.available

    def first(self, *names: str) -> str | None:
        """Return the first installed tool from ``names``, in preference order."""
        for name in names:
            if name in self.available:
                return name
        return None

    def in_category(self, category: str) -> list[str]:
        return [t.name for t in REGISTRY if t.category == category and t.name in self.available]

    def missing(self) -> list[Tool]:
        return [t for t in REGISTRY if t.name not in self.available]

    def summary(self) -> str:
        total = len(REGISTRY)
        if not self.available:
            return f"0/{total} external tools found — running in pure-Python fallback mode."
        return f"{len(self.available)}/{total} external tools found: " + ", ".join(sorted(self.available))


def detect_tools() -> ToolInventory:
    """Scan ``PATH`` (plus the usual Go bin dir) for every registry tool."""
    inv = ToolInventory()
    extra_paths = [
        os.path.expanduser("~/go/bin"),
        os.path.expanduser("~/.local/bin"),
        "/usr/local/bin",
        "/opt/homebrew/bin",
    ]
    search_path = os.pathsep.join(
        [os.environ.get("PATH", "")] + [p for p in extra_paths if os.path.isdir(p)]
    )
    for tool in REGISTRY:
        path = shutil.which(tool.name, path=search_path)
        if path:
            inv.available[tool.name] = path
    return inv


def run(cmd: list[str], timeout: int = 180, input_text: str | None = None,
        cwd: str | None = None) -> tuple[int, str, str]:
    """Run ``cmd`` and capture output as ``(returncode, stdout, stderr)``.

    Missing binaries and timeouts are reported as non-zero return codes rather
    than raised, so every caller can simply fall back to the built-in path.
    """
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return 124, partial, f"{cmd[0]}: timed out after {timeout}s"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "", f"{cmd[0]}: {exc}"
