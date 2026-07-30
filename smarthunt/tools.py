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

CATEGORIES = [
    CAT_SUBDOMAIN, CAT_PERMUTE, CAT_RESOLVE, CAT_PROBE, CAT_PORTS, CAT_CRAWL,
    CAT_JS, CAT_PARAMS, CAT_CONTENT, CAT_VULN, CAT_TAKEOVER, CAT_SCREENSHOT,
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
