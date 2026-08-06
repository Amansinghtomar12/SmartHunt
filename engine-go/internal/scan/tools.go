package scan

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Tool is one external program the engine can drive when it is installed. The
// engine works with zero tools — every stage has a pure-Go fallback — but each
// installed tool widens or deepens a stage. This registry is deliberately large
// because coverage in recon comes from running many sources and merging: no
// single subdomain source or JS analyser finds everything.
type Tool struct {
	Name     string
	Category string
	Desc     string
	Install  string
}

// Registry lists every tool the engine knows how to use. Grouped by stage.
var Registry = []Tool{
	// --- subdomain enumeration ---
	{"subfinder", "subdomain", "Fast passive subdomain discovery across 30+ sources", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
	{"amass", "subdomain", "In-depth attack-surface mapping", "go install github.com/owasp-amass/amass/v4/...@master"},
	{"assetfinder", "subdomain", "Domains and subdomains related to a target", "go install github.com/tomnomnom/assetfinder@latest"},
	{"findomain", "subdomain", "Cross-platform subdomain enumerator", "https://github.com/Findomain/Findomain/releases"},
	{"chaos", "subdomain", "ProjectDiscovery Chaos dataset client", "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest"},
	{"github-subdomains", "subdomain", "Mines GitHub code search for subdomains", "go install github.com/gwen001/github-subdomains@latest"},
	{"shosubgo", "subdomain", "Pulls subdomains from the Shodan API", "go install github.com/incogbyte/shosubgo@latest"},
	// --- permutation ---
	{"dnsgen", "permutation", "Generates permutations of known subdomains", "pipx install dnsgen"},
	{"gotator", "permutation", "DNS wordlist permutation generator", "go install github.com/Josue87/gotator@latest"},
	{"alterx", "permutation", "Pattern-based subdomain permutation", "go install github.com/projectdiscovery/alterx/cmd/alterx@latest"},
	{"puredns", "permutation", "Fast bruteforce with wildcard filtering", "go install github.com/d3mondev/puredns/v2@latest"},
	// --- dns / probing ---
	{"dnsx", "dns", "Fast multi-purpose DNS toolkit", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
	{"massdns", "dns", "High-performance DNS stub resolver", "https://github.com/blechschmidt/massdns"},
	{"httpx", "probe", "Fast, multi-purpose HTTP probe", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
	{"naabu", "ports", "Fast SYN/CONNECT port scanner", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
	// --- crawling / urls ---
	{"katana", "crawl", "Next-generation crawling and spidering", "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
	{"gau", "urls", "Fetch known URLs from AlienVault, Wayback, CommonCrawl", "go install github.com/lc/gau/v2/cmd/gau@latest"},
	{"waybackurls", "urls", "Fetch URLs from the Wayback Machine", "go install github.com/tomnomnom/waybackurls@latest"},
	{"hakrawler", "crawl", "Fast web crawler for endpoint discovery", "go install github.com/hakluke/hakrawler@latest"},
	{"gospider", "crawl", "Fast web spider written in Go", "go install github.com/jaeles-project/gospider@latest"},
	// --- javascript / secrets ---
	{"subjs", "js", "Fetches JavaScript file URLs from a list of hosts", "go install github.com/lc/subjs@latest"},
	{"getjs", "js", "Extract JavaScript references from pages", "go install github.com/003random/getJS@latest"},
	{"trufflehog", "secrets", "Verified secret scanning across many detectors", "go install github.com/trufflesecurity/trufflehog/v3@latest"},
	{"gitleaks", "secrets", "Detect hardcoded secrets", "go install github.com/gitleaks/gitleaks/v8@latest"},
	{"mantra", "secrets", "Hunt API keys in JS files", "go install github.com/MrEmpy/mantra@latest"},
	// --- parameters ---
	{"paramspider", "params", "Mines parameters from web archives", "pipx install paramspider"},
	{"arjun", "params", "HTTP parameter discovery by fuzzing", "pipx install arjun"},
	{"gf", "params", "Pattern grep for interesting URLs/params", "go install github.com/tomnomnom/gf@latest"},
	// --- content discovery ---
	{"ffuf", "content", "Fast web fuzzer for content discovery", "go install github.com/ffuf/ffuf/v2@latest"},
	{"feroxbuster", "content", "Recursive content discovery in Rust", "cargo install feroxbuster"},
	{"dirsearch", "content", "Web path brute-forcer", "pipx install dirsearch"},
	// --- vulnerability scanning ---
	{"nuclei", "vuln", "Template-based vulnerability scanner", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	{"dalfox", "injection", "Powerful XSS scanner and parameter analyzer", "go install github.com/hahwul/dalfox/v2@latest"},
	{"sqlmap", "injection", "Automated SQL injection confirmation", "pipx install sqlmap"},
	{"crlfuzz", "injection", "CRLF injection scanner", "go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"},
	{"corsy", "cors", "CORS misconfiguration scanner", "pipx install corsy"},
	// --- takeover / cloud / tls ---
	{"subzy", "takeover", "Subdomain takeover checker", "go install github.com/PentestPad/subzy@latest"},
	{"nuclei-takeover", "takeover", "Takeover templates (via nuclei -t takeovers)", "part of nuclei"},
	{"s3scanner", "cloud", "Enumerate open S3 buckets", "pipx install s3scanner"},
	{"testssl", "tls", "TLS/SSL configuration testing", "https://github.com/drwetter/testssl.sh"},
	// --- oob / screenshots ---
	{"interactsh-client", "oob", "Out-of-band interaction catcher for SSRF/RCE", "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"},
	{"gowitness", "screenshot", "Screenshot live web hosts", "go install github.com/sensepost/gowitness@latest"},
}

// Inventory records which tools are actually installed.
type Inventory struct {
	present map[string]string // name -> resolved path
}

func detectTools() *Inventory {
	inv := &Inventory{present: map[string]string{}}
	for _, t := range Registry {
		if p, err := exec.LookPath(t.Name); err == nil {
			inv.present[t.Name] = p
		}
	}
	return inv
}

func (inv *Inventory) has(name string) bool { _, ok := inv.present[name]; return ok }

func (inv *Inventory) count() int { return len(inv.present) }

// runTool executes an installed tool, optionally feeding it stdin, and returns
// its stdout lines. It never fails the scan — a tool that errors is skipped.
func runTool(name string, args []string, stdin string, timeout time.Duration) []string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// PrintTools lists the registry with an installed/missing marker.
func PrintTools() {
	inv := detectTools()
	current := ""
	fmt.Printf("\nSmartHunt (Go) — external tool inventory\n")
	for _, t := range Registry {
		if t.Category != current {
			current = t.Category
			fmt.Printf("\n%s\n", strings.ToUpper(current))
		}
		mark := "○"
		if inv.has(t.Name) {
			mark = "●"
		}
		fmt.Printf("  %s %-18s %s\n", mark, t.Name, t.Desc)
	}
	fmt.Printf("\n%d of %d tools installed\n\n", inv.count(), len(Registry))
}
