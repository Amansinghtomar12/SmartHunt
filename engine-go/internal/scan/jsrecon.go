package scan

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Secret is a credential-shaped string found in a JavaScript bundle. It is a
// LEAD, never a confirmed finding: many are placeholders or publishable keys,
// and confirming one requires knowing it is live. Deduplicated by value so the
// same bundle served from a hundred subdomains is one lead, not a hundred.
type Secret struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Source   string `json:"source"`
	Severity string `json:"severity"`
}

type secretRule struct {
	name     string
	re       *regexp.Regexp
	severity string
}

var secretRules = []secretRule{
	{"AWS access key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "high"},
	{"Stripe live key", regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{16,}`), "critical"},
	{"Google API key", regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{35}`), "medium"},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}`), "high"},
	{"SendGrid key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`), "high"},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}`), "low"},
	{"Slack webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]+`), "medium"},
}

// endpointRe pulls path-like strings out of a bundle — future request targets.
var endpointRe = regexp.MustCompile(`["'` + "`" + `](/(?:api|v\d|graphql|rest|internal|admin|user|account|auth)[A-Za-z0-9_./?=&{}-]*)["'` + "`" + `]`)

// placeholder values that look like secrets but are not — the single biggest
// source of secret false positives.
var placeholderRe = regexp.MustCompile(`(?i)your[_-]?(api|secret|key|token)|example|xxxx|placeholder|<[a-z_]+>|changeme|dummy`)

// analyzeJS fetches each bundle and mines endpoints and secrets, concurrently.
func (e *Engine) analyzeJS(jsFiles []string) (endpoints []string, secrets []Secret) {
	var mu sync.Mutex
	seenSecret := map[string]bool{}
	seenEndpoint := map[string]bool{}
	e.each(jsFiles, func(jsURL string) {
		x := e.client.capture("GET", jsURL, "fetch JS bundle", nil)
		if x.Err != "" || x.Status != 200 {
			return
		}
		var localEnd []string
		for _, m := range endpointRe.FindAllStringSubmatch(x.RespBody, -1) {
			localEnd = append(localEnd, m[1])
		}
		var localSec []Secret
		for _, r := range secretRules {
			for _, v := range r.re.FindAllString(x.RespBody, -1) {
				if placeholderRe.MatchString(v) {
					continue
				}
				localSec = append(localSec, Secret{Type: r.name, Value: v, Source: jsURL, Severity: r.severity})
			}
		}
		mu.Lock()
		for _, ep := range localEnd {
			if !seenEndpoint[ep] {
				seenEndpoint[ep] = true
				endpoints = append(endpoints, ep)
			}
		}
		for _, s := range localSec {
			key := s.Type + "|" + s.Value
			if !seenSecret[key] {
				seenSecret[key] = true
				secrets = append(secrets, s)
			}
		}
		mu.Unlock()
	})
	sort.Strings(endpoints)
	return endpoints, secrets
}

func trimJS(s string) string { return strings.TrimSpace(s) }
