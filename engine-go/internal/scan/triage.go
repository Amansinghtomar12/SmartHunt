package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// This file is the whole reason the tool exists: it turns a noisy finding set
// into either ONE proven, reportable finding or an honest "nothing". Two rules
// do the work, and they are the same rules the Python engine converged on —
// ported here so the Go engine is correct by construction, not later.

// classifyConfidence returns (proven, shownSeverity). A finding keeps its
// severity only if this engine captured first-hand evidence of the behaviour
// and rated it high-confidence, or it is the two-account IDOR. Everything else
// is a LEAD, shown at "info" and never counted as critical/high. A lead dressed
// as critical is precisely a false positive, so this is where they die.
func classifyConfidence(f *Finding) (bool, string) {
	if f.Source == "accesscontrol" {
		return true, f.Severity
	}
	if f.Evidence != nil && len(f.Evidence.Exchanges) > 0 && f.Confidence == "high" {
		return true, f.Severity
	}
	return false, "info"
}

// enrich stamps the honest labelling onto a finding for display and export.
func enrich(f *Finding) {
	proven, shown := classifyConfidence(f)
	f.Proven = proven
	if f.Claimed == "" {
		f.Claimed = f.Severity
	}
	f.Severity = shown
}

// neverReport are classes that are never a standalone report however many turn
// up — informational, hardening-only, or inference. They are the leads.
var neverReport = []*regexp.Regexp{
	regexp.MustCompile(`(?i)missing security headers?|clickjack|hsts|csp\b`),
	regexp.MustCompile(`(?i)outdated component|version disclosure|server banner`),
	regexp.MustCompile(`(?i)possible cve-|^cve-\d{4}`),
	regexp.MustCompile(`(?i)directory listing|autoindex`),
	regexp.MustCompile(`(?i)cookie flags?|httponly|samesite`),
	regexp.MustCompile(`(?i)endpoint discovered|interesting path|js endpoint`),
	regexp.MustCompile(`(?i)^possible |^potential |secret in js`),
	regexp.MustCompile(`(?i)technology disclosed|x-powered-by`),
	regexp.MustCompile(`(?i)third-party cname|takeover`),
	regexp.MustCompile(`(?i)served over plain http`),
}

// classPriority ranks equally-proven findings by how much the attacker gains
// from the *demonstrated* behaviour — not by the bug class's reputation.
func classPriority(name string) int {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "broken access control"), strings.Contains(n, "idor"):
		return 0
	case strings.Contains(n, "sql injection"):
		return 1
	case strings.Contains(n, "template injection"):
		return 2
	case strings.Contains(n, "path traversal"):
		return 3
	case strings.Contains(n, "exposed"):
		return 4
	case strings.Contains(n, "xss"):
		return 6
	}
	return 9
}

// Report is the single triaged outcome.
type Report struct {
	Kind          string   `json:"kind"` // "report" | "none"
	Severity      string   `json:"severity,omitempty"`
	Justification string   `json:"justification,omitempty"`
	Finding       *Finding `json:"finding,omitempty"`
	Considered    int      `json:"considered"`
	Dropped       int      `json:"dropped"`
	Markdown      string   `json:"markdown"`
}

func lockedSeverity(f *Finding) (string, string) {
	n := strings.ToLower(f.Name)
	switch {
	case strings.Contains(n, "broken access control"), strings.Contains(n, "idor"):
		return "high", "Attacker A received Victim B's private object while the unauthenticated request was refused; cross-account read is demonstrated, not inferred."
	case strings.Contains(n, "sql injection"):
		return "high", "Injection into the SQL parser is proven by the database error; data extraction was not attempted, so this is not graded Critical."
	case strings.Contains(n, "template injection"):
		return "high", "The server evaluated an injected expression; command execution was not attempted, so this is not graded Critical."
	case strings.Contains(n, "path traversal"):
		return "high", "An unauthenticated request reads files outside the web root, proven by the returned file contents."
	case strings.Contains(n, "exposed"):
		return "high", "Credential material is disclosed to unauthenticated clients; the credentials were not used, so no further access is claimed."
	case strings.Contains(n, "xss"):
		return "medium", "Injected markup is returned unencoded and executes for whoever opens the crafted link; no victim session was compromised."
	}
	return "low", "Graded on the demonstrated behaviour only."
}

// buildReport applies the evidence gate and returns the single strongest
// reportable finding, or "none". Only findings that already carry captured
// evidence can win — the same gate that keeps false positives out of the list
// keeps them out of the report.
func buildReport(findings []*Finding, target string) Report {
	var candidates []*Finding
	dropped := 0
	for _, f := range findings {
		skip := false
		for _, re := range neverReport {
			if re.MatchString(f.Name) {
				skip = true
				break
			}
		}
		// A finding with no captured evidence can never be the report.
		if f.Evidence == nil || len(f.Evidence.Exchanges) == 0 || f.Confidence != "high" {
			if f.Source != "accesscontrol" {
				skip = true
			}
		}
		if skip {
			dropped++
			continue
		}
		candidates = append(candidates, f)
	}
	if len(candidates) == 0 {
		r := Report{Kind: "none", Considered: len(findings), Dropped: dropped}
		r.Markdown = fmt.Sprintf("# No reportable vulnerability\n\nNo reportable vulnerability found with the current evidence.\n\nConsidered %d finding(s); %d were informational, hardening-only, or unverified leads.\n", len(findings), dropped)
		return r
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		si, sj := severityRank[candidates[i].Severity], severityRank[candidates[j].Severity]
		if si != sj {
			return si < sj
		}
		return classPriority(candidates[i].Name) < classPriority(candidates[j].Name)
	})
	best := candidates[0]
	sev, just := lockedSeverity(best)
	r := Report{Kind: "report", Severity: sev, Justification: just, Finding: best,
		Considered: len(findings), Dropped: dropped}
	r.Markdown = renderMarkdown(best, sev, just, len(findings), dropped, target)
	return r
}

func renderMarkdown(f *Finding, sev, just string, considered, dropped int, target string) string {
	host := f.Host
	if host == "" {
		host = target
	}
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("# %s\n", f.Name)
	w("\n**Severity:** %s — %s\n", strings.Title(sev), just)
	w("\n**OWASP:** %s\n", nz(f.OWASP, "—"))
	w("\n## Summary\n\n%s\n", nz(f.Impact, f.Detail))
	w("\n## Affected Component\n\n")
	w("- **Endpoint:** `%s`\n", f.Endpoint)
	w("- **Method:** `%s`\n", nz(f.Method, "GET"))
	w("- **Parameter / field:** `%s`\n", nz(f.Param, "—"))
	w("- **Host:** `%s`\n", host)
	w("\n## Steps to Reproduce\n\n")
	for i, x := range f.Evidence.Exchanges {
		w("%d. %s:\n   ```\n   curl -i -s -X %s '%s'\n   ```\n   Server returns `%d`.\n",
			i+1, nz(x.Note, "send the request"), x.Method, x.URL, x.Status)
	}
	w("\n## Proof of Concept\n\n")
	for i, x := range f.Evidence.Exchanges {
		w("**Request %d** — %s\n\n```http\n%s\n```\n\n", i+1, x.Note, rawRequest(x, host))
		w("**Response %d**\n\n```http\n%s\n```\n\n", i+1, rawResponse(x, host))
	}
	w("## Impact\n\n- **Proven:** %s\n- **Security boundary crossed:** %s\n", f.Impact, f.Boundary)
	w("\n## Expected vs Actual\n\n- **Expected:** %s\n- **Actual:** %s\n", f.Expected, f.Actual)
	repro := fmt.Sprintf("Reproduced %d× total", f.Evidence.Reproduced)
	if f.Evidence.Unauthenticated {
		repro += ", unauthenticated"
	}
	w("\n## Reproduction Reliability\n\n%s.\n", repro)
	w("\n## Remediation\n\n")
	for _, r := range f.Remedy {
		w("- %s\n", r)
	}
	w("\n---\n\nSelected from %d scan finding(s); %d were informational, hardening-only, or unverified leads and are not reportable on their own. Credentials and personal data above are masked.\n", considered, dropped)
	return b.String()
}

func rawRequest(x Exchange, host string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", x.Method, pathOf(x.URL)))
	b.WriteString("Host: " + hostOf(x.URL) + "\n")
	for k, v := range x.ReqHeaders {
		b.WriteString(k + ": " + v + "\n")
	}
	if x.ReqBody != "" {
		b.WriteString("\n" + x.ReqBody)
	}
	return maskHost(mask(b.String()), host)
}

func rawResponse(x Exchange, host string) string {
	if x.Err != "" {
		return "(no response: " + x.Err + ")"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("HTTP/1.1 %d\n", x.Status))
	for k, v := range x.RespHeaders {
		b.WriteString(k + ": " + v + "\n")
	}
	body := x.RespBody
	if len(body) > maxBody {
		body = body[:maxBody] + "\n… [truncated]"
	}
	b.WriteString("\n" + body)
	return maskHost(mask(b.String()), host)
}

func pathOf(rawURL string) string {
	i := strings.Index(rawURL, "://")
	if i < 0 {
		return rawURL
	}
	rest := rawURL[i+3:]
	if j := strings.Index(rest, "/"); j >= 0 {
		return rest[j:]
	}
	return "/"
}

func nz(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
