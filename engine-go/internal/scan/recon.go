package scan

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Host is one live web host and what we learned about it.
type Host struct {
	Host   string   `json:"host"`
	URL    string   `json:"url"`
	Status int      `json:"status"`
	Title  string   `json:"title"`
	Server string   `json:"server"`
	Tech   []string `json:"tech"`
	IPs    []string `json:"ips"`
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// probeHosts resolves and HTTP-probes a set of hostnames concurrently, keeping
// only the ones that answer. This is the stage goroutines make cheap: hundreds
// of hosts are probed at once, bounded by the worker pool, not serialised.
func (e *Engine) probeHosts(hosts []string) map[string]*Host {
	type result struct {
		h *Host
	}
	out := map[string]*Host{}
	var mu sync.Mutex
	e.each(hosts, func(host string) {
		ips, _ := net.LookupHost(host)
		var live *Host
		for _, scheme := range []string{"https", "http"} {
			base := scheme + "://" + host
			x := e.client.capture("GET", base+"/", "http probe", nil)
			if x.Err != "" || x.Status == 0 {
				continue
			}
			h := &Host{Host: host, URL: x.URL, Status: x.Status,
				Server: x.RespHeaders["Server"], IPs: ips}
			if m := titleRe.FindStringSubmatch(x.RespBody); m != nil {
				h.Title = strings.TrimSpace(collapse(m[1]))
			}
			h.Tech = fingerprint(x)
			live = h
			break
		}
		if live != nil {
			mu.Lock()
			out[host] = live
			mu.Unlock()
		}
	})
	return out
}

func fingerprint(x Exchange) []string {
	var tech []string
	add := func(s string) {
		if s != "" {
			tech = append(tech, s)
		}
	}
	add(x.RespHeaders["Server"])
	add(x.RespHeaders["X-Powered-By"])
	if x.RespHeaders["X-Generator"] != "" {
		add(x.RespHeaders["X-Generator"])
	}
	body := strings.ToLower(x.RespBody)
	for _, sig := range []struct{ needle, name string }{
		{"wp-content", "WordPress"}, {"drupal", "Drupal"}, {"/_next/", "Next.js"},
		{"react", "React"}, {"ng-version", "Angular"}, {"laravel_session", "Laravel"},
	} {
		if strings.Contains(body, sig.needle) {
			add(sig.name)
		}
	}
	return dedup(tech)
}

var (
	hrefRe = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)["']`)
	// Two ways a bundle is referenced: a src=/href= attribute, or a bare quoted
	// path ending in .js inside script. Both feed the JS analyser.
	jsSrcRe   = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"'\s]+?\.js(?:\?[^"']*)?)["']`)
	jsQuoteRe = regexp.MustCompile(`(?i)["'` + "`" + `]([^"'` + "`" + `\s]+?\.js(?:\?[^"'` + "`" + `]*)?)["'` + "`" + `]`)
)

// crawl fetches each seed and one level of same-host links, collecting URLs and
// JavaScript file references. Bounded by maxPages so it always terminates.
func (e *Engine) crawl(seeds []*Host) (urls, jsFiles []string) {
	// Separate dedup sets: the href regex also matches script src=, so a shared
	// map would let a .js be claimed as a URL and then skipped by the JS loop —
	// which is exactly how the JS stage silently collected nothing.
	seenURL := map[string]bool{}
	seenJS := map[string]bool{}
	var mu sync.Mutex
	var seedURLs []string
	for _, h := range seeds {
		seedURLs = append(seedURLs, h.URL)
	}
	e.each(seedURLs, func(seed string) {
		base, err := url.Parse(seed)
		if err != nil {
			return
		}
		x := e.client.capture("GET", seed, "crawl", nil)
		if x.Err != "" {
			return
		}
		var localURLs, localJS []string
		for _, m := range hrefRe.FindAllStringSubmatch(x.RespBody, -1) {
			if abs := resolve(base, m[1]); abs != "" && sameHost(base, abs) {
				localURLs = append(localURLs, abs)
			}
		}
		for _, re := range []*regexp.Regexp{jsSrcRe, jsQuoteRe} {
			for _, m := range re.FindAllStringSubmatch(x.RespBody, -1) {
				if abs := resolve(base, m[1]); abs != "" {
					localJS = append(localJS, abs)
				}
			}
		}
		mu.Lock()
		for _, u := range localURLs {
			if !seenURL[u] && len(urls) < e.cfg.MaxPages {
				seenURL[u] = true
				urls = append(urls, u)
			}
		}
		for _, j := range localJS {
			if !seenJS[j] {
				seenJS[j] = true
				jsFiles = append(jsFiles, j)
			}
		}
		mu.Unlock()
	})
	return dedup(urls), dedup(jsFiles)
}

func resolve(base *url.URL, ref string) string {
	u, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ""
	}
	r := base.ResolveReference(u)
	if r.Scheme != "http" && r.Scheme != "https" {
		return ""
	}
	r.Fragment = ""
	return r.String()
}

func sameHost(a *url.URL, rawURL string) bool {
	b, err := url.Parse(rawURL)
	return err == nil && b.Hostname() == a.Hostname()
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
