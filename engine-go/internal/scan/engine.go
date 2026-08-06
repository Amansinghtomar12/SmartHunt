package scan

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config is everything a scan needs. Sensible defaults keep a fresh clone
// working with no flags.
type Config struct {
	Target     string
	Wildcard   bool
	Threads    int
	Timeout    time.Duration
	CrawlDepth int
	MaxPages   int
	MaxJSFiles int
	AuthHeader map[string]string // an already-authenticated session, optional
}

func (c *Config) defaults() {
	if c.Threads <= 0 {
		c.Threads = 50
	}
	if c.Timeout <= 0 {
		c.Timeout = 12 * time.Second
	}
	if c.MaxPages <= 0 {
		c.MaxPages = 400
	}
	if c.MaxJSFiles <= 0 {
		c.MaxJSFiles = 300
	}
}

// Results is everything a scan produced.
type Results struct {
	Target     string     `json:"target"`
	Mode       string     `json:"mode"`
	DurationS  float64    `json:"duration_seconds"`
	Subdomains []string   `json:"subdomains"`
	Hosts      []*Host    `json:"hosts"`
	URLs       []string   `json:"urls"`
	JSFiles    []string   `json:"js_files"`
	Endpoints  []string   `json:"js_endpoints"`
	Secrets    []Secret   `json:"secrets"`
	Findings   []*Finding `json:"findings"`
	Report     Report     `json:"report"`
	ToolsUsed  []string   `json:"tools_used"`
}

// Stats returns the honest headline numbers — Confirmed and Critical/High count
// only proven findings, never leads.
func (r *Results) Stats() map[string]int {
	proven, critHigh := 0, 0
	for _, f := range r.Findings {
		if f.Proven {
			proven++
			if f.Severity == "critical" || f.Severity == "high" {
				critHigh++
			}
		}
	}
	return map[string]int{
		"subdomains": len(r.Subdomains), "live_hosts": len(r.Hosts),
		"urls": len(r.URLs), "js_files": len(r.JSFiles), "endpoints": len(r.Endpoints),
		"secrets": len(r.Secrets), "findings": len(r.Findings),
		"confirmed": proven, "critical_high": critHigh,
	}
}

// Engine runs a Config. The log callback receives human-readable progress.
type Engine struct {
	cfg    *Config
	client *Client
	inv    *Inventory
	log    func(level, msg string)
	sem    chan struct{}
}

// New builds an engine.
func New(cfg *Config, log func(level, msg string)) *Engine {
	cfg.defaults()
	if log == nil {
		log = func(string, string) {}
	}
	return &Engine{
		cfg:    cfg,
		client: newClient(cfg.Timeout, cfg.AuthHeader),
		inv:    detectTools(),
		log:    log,
		sem:    make(chan struct{}, cfg.Threads),
	}
}

// each runs fn over items with bounded concurrency — the core of why this is in
// Go: thousands of network calls in flight at once, capped by the worker pool.
func (e *Engine) each(items []string, fn func(string)) {
	var wg sync.WaitGroup
	for _, it := range items {
		wg.Add(1)
		e.sem <- struct{}{}
		go func(x string) {
			defer wg.Done()
			defer func() { <-e.sem }()
			fn(x)
		}(it)
	}
	wg.Wait()
}

// Run executes the full pipeline and returns the Results.
func (e *Engine) Run() *Results {
	start := time.Now()
	apex := normalizeTarget(e.cfg.Target)
	mode := "domain"
	if e.cfg.Wildcard {
		mode = "wildcard"
	}
	res := &Results{Target: apex, Mode: mode, ToolsUsed: e.toolsUsed()}
	e.log("stage", fmt.Sprintf("SmartHunt (Go) — target %s, mode %s, %d tools, %d workers",
		apex, mode, e.inv.count(), e.cfg.Threads))

	// 1. subdomain enumeration (wildcard) or the single host (domain)
	var hosts []string
	if e.cfg.Wildcard {
		e.log("stage", "▶ Subdomain enumeration")
		hosts = e.enumerate(apex)
		res.Subdomains = hosts
		e.log("info", fmt.Sprintf("  %d candidate hosts", len(hosts)))
	} else {
		hosts = []string{apex}
	}

	// 2. HTTP probe (concurrent)
	e.log("stage", "▶ HTTP probing")
	live := e.probeHosts(hosts)
	for _, h := range live {
		res.Hosts = append(res.Hosts, h)
	}
	sort.Slice(res.Hosts, func(i, j int) bool { return res.Hosts[i].Host < res.Hosts[j].Host })
	if len(live) == 0 {
		// Keep going against the apex so a domain scan still runs.
		live[apex] = &Host{Host: apex, URL: "https://" + apex}
		res.Hosts = []*Host{live[apex]}
	}
	e.log("info", fmt.Sprintf("  %d live host(s)", len(live)))

	// 3. crawl + URL collection
	e.log("stage", "▶ URL / endpoint collection")
	seeds := make([]*Host, 0, len(live))
	for _, h := range live {
		seeds = append(seeds, h)
	}
	urls, jsFiles := e.crawl(seeds)
	if len(jsFiles) > e.cfg.MaxJSFiles {
		jsFiles = jsFiles[:e.cfg.MaxJSFiles]
	}
	res.URLs = urls
	res.JSFiles = jsFiles

	// 4. JS analysis (endpoints + secrets, deduped)
	e.log("stage", "▶ JavaScript analysis")
	endpoints, secrets := e.analyzeJS(jsFiles)
	res.Endpoints = endpoints
	res.Secrets = secrets
	for _, u := range endpoints {
		if strings.HasPrefix(u, "http") {
			urls = append(urls, u)
		}
	}
	// Join mined path endpoints onto every live host so they become callable.
	for _, ep := range endpoints {
		if strings.HasPrefix(ep, "/") {
			for _, h := range live {
				urls = append(urls, strings.TrimRight(h.URL, "/")+ep)
			}
		}
	}
	urls = dedup(urls)
	res.URLs = urls

	var findings []*Finding
	// Secrets become leads (never criticals — dedup already applied).
	for _, s := range secrets {
		findings = append(findings, &Finding{
			Host: apex, Name: "Secret in JS: " + s.Type, Severity: s.Severity,
			Claimed: s.Severity, Source: "jsrecon", Confidence: "low",
			Detail: s.Value + "  (" + s.Source + ")",
		})
	}

	// 5. active OWASP checks (concurrent, evidence-capturing)
	e.log("stage", "▶ Active checks (OWASP)")
	findings = append(findings, e.activeChecks(urls, live)...)

	// 6. exposed sensitive files
	for _, h := range live {
		for _, ef := range []struct{ path, what string }{
			{"/.env", ".env deployment file"}, {"/.git/config", ".git repository config"},
		} {
			if f := e.client.checkExposedFile(h.URL, ef.path, ef.what); f != nil {
				findings = append(findings, f)
				e.log("found", "  [high] "+f.Name+" on "+h.Host)
			}
		}
	}

	// 7. triage → one proven finding + honest labelling on the whole list
	e.log("stage", "▶ Triage — selecting the single strongest finding")
	res.Report = buildReport(findings, apex)
	for _, f := range findings {
		enrich(f)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		pi, pj := 0, 0
		if !findings[i].Proven {
			pi = 1
		}
		if !findings[j].Proven {
			pj = 1
		}
		if pi != pj {
			return pi < pj
		}
		return severityRank[findings[i].Claimed] < severityRank[findings[j].Claimed]
	})
	res.Findings = findings

	res.DurationS = time.Since(start).Seconds()
	st := res.Stats()
	if res.Report.Kind == "report" {
		e.log("found", fmt.Sprintf("  ✓ reportable: %s [%s]", res.Report.Finding.Name, res.Report.Severity))
	}
	e.log("stage", fmt.Sprintf("Done in %.1fs — %d confirmed, %d critical/high, %d leads",
		res.DurationS, st["confirmed"], st["critical_high"], st["findings"]-st["confirmed"]))
	return res
}

// activeChecks fans the injection checks across every parameterised URL.
func (e *Engine) activeChecks(urls []string, live map[string]*Host) []*Finding {
	// Deduplicate by (host, path, sorted-params) so the same shape is tested once.
	seen := map[string]bool{}
	var targets []string
	for _, u := range urls {
		params := paramsOf(u)
		if len(params) == 0 {
			continue
		}
		pu, err := url.Parse(u)
		if err != nil {
			continue
		}
		sort.Strings(params)
		key := pu.Host + pu.Path + "|" + strings.Join(params, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, u)
	}

	var mu sync.Mutex
	var findings []*Finding
	e.each(targets, func(u string) {
		baseline := e.client.capture("GET", u, "baseline, unmodified request", nil)
		if baseline.Err != "" {
			return
		}
		for _, param := range paramsOf(u) {
			for _, check := range []func(string, string, Exchange) *Finding{
				e.client.checkSQLi, e.client.checkSSTI, e.client.checkTraversal, e.client.checkXSS,
			} {
				if f := check(u, param, baseline); f != nil {
					mu.Lock()
					findings = append(findings, f)
					mu.Unlock()
					e.log("found", fmt.Sprintf("  [%s] %s", f.Severity, f.Name))
				}
			}
		}
	})
	return findings
}

// enumerate finds subdomains: installed tools first (subfinder/assetfinder),
// then a built-in bruteforce with wildcard-DNS detection so a catch-all domain
// does not "discover" thousands of hosts that do not exist.
func (e *Engine) enumerate(apex string) []string {
	found := map[string]bool{apex: true}
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == apex || strings.HasSuffix(h, "."+apex) {
			found[h] = true
		}
	}
	for _, spec := range []struct {
		tool string
		args []string
	}{
		{"subfinder", []string{"-silent", "-d", apex}},
		{"assetfinder", []string{"--subs-only", apex}},
		{"findomain", []string{"-t", apex, "-q"}},
	} {
		if e.inv.has(spec.tool) {
			for _, line := range runTool(spec.tool, spec.args, "", 120*time.Second) {
				add(line)
			}
		}
	}
	// Built-in bruteforce fallback, with wildcard detection.
	wildcardIP := wildcardAddress(apex)
	for _, w := range builtinSubdomains {
		cand := w + "." + apex
		if ips, err := net.LookupHost(cand); err == nil && len(ips) > 0 {
			if wildcardIP != "" && ips[0] == wildcardIP {
				continue // resolves only to the catch-all — not a real host
			}
			add(cand)
		}
	}
	var out []string
	for h := range found {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// wildcardAddress returns the address a guaranteed-nonexistent name resolves to,
// or "" if the domain does not answer every name.
func wildcardAddress(apex string) string {
	if ips, err := net.LookupHost("smarthunt-nonexistent-probe-zzz." + apex); err == nil && len(ips) > 0 {
		return ips[0]
	}
	return ""
}

func (e *Engine) toolsUsed() []string {
	var out []string
	for _, t := range Registry {
		if e.inv.has(t.Name) {
			out = append(out, t.Name)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeTarget(raw string) string {
	t := strings.ToLower(strings.TrimSpace(raw))
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "*.")
	t = strings.TrimPrefix(t, ".")
	if i := strings.IndexAny(t, "/?:@"); i >= 0 {
		t = t[:i]
	}
	return strings.Trim(t, ".")
}

// builtinSubdomains is a small, high-signal fallback list for when no external
// enumeration tool is installed.
var builtinSubdomains = []string{
	"www", "api", "app", "admin", "dev", "staging", "test", "portal", "mail",
	"webmail", "vpn", "remote", "git", "gitlab", "jenkins", "jira", "confluence",
	"dashboard", "internal", "beta", "demo", "cdn", "static", "assets", "img",
	"media", "docs", "support", "help", "status", "monitor", "grafana", "kibana",
	"prometheus", "s3", "storage", "backup", "db", "database", "auth", "sso",
	"login", "account", "accounts", "billing", "payment", "shop", "store",
	"blog", "news", "m", "mobile", "secure", "gateway", "proxy", "ns1", "ns2",
}

// Normalize exposes normalizeTarget for the CLI.
func Normalize(raw string) string { return normalizeTarget(raw) }
