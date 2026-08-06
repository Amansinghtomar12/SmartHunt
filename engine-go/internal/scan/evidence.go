// Package scan is the SmartHunt reconnaissance and vulnerability engine, in Go.
//
// The design principle is the same one the Python engine ended up at, and the
// reason for the port is concurrency: a recon scan is thousands of independent
// network round-trips, which goroutines express directly and cheaply. What does
// NOT change is the evidence rule — a finding is only ever "confirmed" if this
// engine captured the request and response that prove it. Everything else is a
// lead. That rule lives in triage.go and is enforced for every finding, so the
// "every critical was a false positive" failure cannot recur here.
package scan

import (
	"regexp"
	"strings"
)

// maxBody bounds how much of a response body is kept per exchange — enough to
// prove a point without holding whole pages in memory across a big scan.
const maxBody = 4096

// Exchange is one request/response pair, recorded verbatim for a report.
type Exchange struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	ReqHeaders  map[string]string `json:"request_headers,omitempty"`
	ReqBody     string            `json:"request_body,omitempty"`
	Status      int               `json:"status"`
	RespHeaders map[string]string `json:"response_headers,omitempty"`
	RespBody    string            `json:"response_body,omitempty"`
	ElapsedMs   int64             `json:"elapsed_ms"`
	Note        string            `json:"note,omitempty"`
	Err         string            `json:"error,omitempty"`
}

// Evidence is everything needed to prove one finding.
type Evidence struct {
	Exchanges       []Exchange `json:"exchanges"`
	Reproduced      int        `json:"reproduced"`
	FreshSession    bool       `json:"fresh_session"`
	Unauthenticated bool       `json:"unauthenticated"`
}

func (e *Evidence) add(x Exchange) { e.Exchanges = append(e.Exchanges, x) }

// --- credential masking -----------------------------------------------------
//
// Every string that can reach a report passes through mask(). A security tool
// that leaks the very secrets it finds is worse than useless, so the masking is
// deliberately broad and runs on the way out of the engine, not as an
// afterthought in the presentation layer.

type maskRule struct {
	re   *regexp.Regexp
	repl string
}

var maskRules = []maskRule{
	{regexp.MustCompile(`(?i)\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}`), "JWT_TOKEN"},
	{regexp.MustCompile(`(?i)\bgh[pousr]_[A-Za-z0-9]{20,}`), "GITHUB_TOKEN"},
	{regexp.MustCompile(`(?i)\bsk_live_[A-Za-z0-9]{10,}`), "STRIPE_LIVE_KEY"},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{12,}`), "AWS_ACCESS_KEY"},
	{regexp.MustCompile(`(?i)\bSG\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}`), "SENDGRID_KEY"},
	{regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{30,}`), "GOOGLE_API_KEY"},
	// KEY=value / KEY: value assignments, anywhere in a body — not only at the
	// start of a line, so a secret inside JSON or a query string is caught too.
	{regexp.MustCompile(`(?im)((?:^|[\s"',;(\[{&?])\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE|CREDENTIAL)[A-Z0-9_]*\s*[=:]\s*)([^\s"',;)\]}&]+)`), "${1}REDACTED_SECRET"},
	{regexp.MustCompile(`(?i)(["']?(?:password|passwd|secret|token|api_?key|private_?key)["']?\s*:\s*)["']([^"']{3,})["']`), `${1}"REDACTED_SECRET"`},
	{regexp.MustCompile(`(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), "TEST_EMAIL"},
}

func mask(s string) string {
	for _, r := range maskRules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// maskHost swaps a real hostname for TARGET_HOST so a report can be shared.
func maskHost(s, host string) string {
	if host == "" {
		return s
	}
	return strings.ReplaceAll(s, host, "TARGET_HOST")
}
