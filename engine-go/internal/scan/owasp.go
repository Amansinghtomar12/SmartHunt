package scan

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// The active checks. Each one sends a bounded, non-destructive request, and
// returns a Finding ONLY when it captured a response that demonstrates the flaw
// — never on a hunch. Every Finding it returns carries the Evidence that proves
// it, which is what lets triage grade it "confirmed".

const marker = "1447" // an unusual constant that is unlikely to occur by chance

var sqlErrors = []struct {
	re     *regexp.Regexp
	engine string
}{
	{regexp.MustCompile(`(?i)SQL syntax.*MySQL|check the manual that corresponds to your (MySQL|MariaDB)`), "MySQL"},
	{regexp.MustCompile(`(?i)PostgreSQL.*ERROR|pg_query\(\)|unterminated quoted string at or near`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string`), "MSSQL"},
	{regexp.MustCompile(`(?i)SQLite3?::|sqlite3\.OperationalError|SQLITE_ERROR`), "SQLite"},
	{regexp.MustCompile(`(?i)ORA-\d{5}|Oracle error|quoted string not properly terminated`), "Oracle"},
}

var passwdRe = regexp.MustCompile(`root:.?:0:0:`)

// mutate replaces (or adds) a query parameter's value.
func mutate(rawURL, param, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func paramsOf(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var out []string
	for k := range u.Query() {
		out = append(out, k)
	}
	return out
}

func (c *Client) checkSQLi(rawURL, param string, baseline Exchange) *Finding {
	probe := c.capture("GET", mutate(rawURL, param, "'"), fmt.Sprintf("single quote injected into '%s'", param), nil)
	if probe.Err != "" {
		return nil
	}
	engine := ""
	for _, e := range sqlErrors {
		if e.re.MatchString(probe.RespBody) && !e.re.MatchString(baseline.RespBody) {
			engine = e.engine
			break
		}
	}
	if engine == "" {
		return nil
	}
	ev := &Evidence{Unauthenticated: true}
	ev.add(baseline)
	ev.add(probe)
	ev.Reproduced = 1 + c.verifyRepeat(probe, func(r Exchange) bool {
		for _, e := range sqlErrors {
			if e.re.MatchString(r.RespBody) {
				return true
			}
		}
		return false
	}, 2)
	return &Finding{
		Host: hostOf(rawURL), Name: fmt.Sprintf("SQL injection (%s) in '%s'", engine, param),
		Severity: "critical", Claimed: "critical", Source: "owasp", Confidence: "high",
		Evidence: ev, OWASP: "A03:2021 Injection", Endpoint: rawURL, Method: "GET", Param: param,
		Detail:   fmt.Sprintf("A single quote in '%s' produces a %s parser error, absent from the baseline.", param, engine),
		Boundary: "Untrusted input reaches the SQL query parser",
		Expected: fmt.Sprintf("'%s' is bound as a parameter; a quote is treated as data", param),
		Actual:   fmt.Sprintf("The server returned a %s syntax error echoing the injected quote", engine),
		Impact:   "Input to the parameter is interpreted as SQL by the database backend.",
		Remedy: []string{
			"Use parameterised queries / prepared statements for every value",
			"Never build SQL by string concatenation with request data",
			"Return generic error pages; never expose database parser errors",
		},
	}
}

func (c *Client) checkSSTI(rawURL, param string, baseline Exchange) *Finding {
	// 7*13 = 91: a distinctive product that plain reflection cannot produce.
	probe := c.capture("GET", mutate(rawURL, param, "{{7*13}}"), fmt.Sprintf("template expression injected into '%s'", param), nil)
	if probe.Err != "" || !strings.Contains(probe.RespBody, "91") || strings.Contains(probe.RespBody, "{{7*13}}") {
		return nil
	}
	// Guard against a coincidental "91" already in the baseline.
	if strings.Contains(baseline.RespBody, "91") {
		return nil
	}
	ev := &Evidence{Unauthenticated: true}
	ev.add(baseline)
	ev.add(probe)
	ev.Reproduced = 1 + c.verifyRepeat(probe, func(r Exchange) bool {
		return strings.Contains(r.RespBody, "91") && !strings.Contains(r.RespBody, "{{7*13}}")
	}, 2)
	return &Finding{
		Host: hostOf(rawURL), Name: fmt.Sprintf("Server-side template injection in '%s'", param),
		Severity: "critical", Claimed: "critical", Source: "owasp", Confidence: "high",
		Evidence: ev, OWASP: "A03:2021 Injection", Endpoint: rawURL, Method: "GET", Param: param,
		Detail:   fmt.Sprintf("'%s' evaluated {{7*13}} to 91 server-side.", param),
		Boundary: "Untrusted input is evaluated by the template engine",
		Expected: "The expression is rendered literally, not evaluated",
		Actual:   "The server returned 91, the product of the injected expression",
		Impact:   "The server evaluated an attacker-supplied template expression.",
		Remedy: []string{
			"Never pass user input into the template as code; pass it as data",
			"Use a sandboxed or logic-less template engine",
		},
	}
}

func (c *Client) checkTraversal(rawURL, param string, baseline Exchange) *Finding {
	payloads := []string{"../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"}
	for _, p := range payloads {
		probe := c.capture("GET", mutate(rawURL, param, p), fmt.Sprintf("path traversal via '%s'", param), nil)
		if probe.Err != "" || !passwdRe.MatchString(probe.RespBody) {
			continue
		}
		ev := &Evidence{Unauthenticated: true}
		ev.add(baseline)
		ev.add(probe)
		ev.Reproduced = 1 + c.verifyRepeat(probe, func(r Exchange) bool { return passwdRe.MatchString(r.RespBody) }, 2)
		return &Finding{
			Host: hostOf(rawURL), Name: fmt.Sprintf("Path traversal in '%s'", param),
			Severity: "high", Claimed: "high", Source: "owasp", Confidence: "high",
			Evidence: ev, OWASP: "A01:2021 Broken Access Control", Endpoint: rawURL, Method: "GET", Param: param,
			Detail:   fmt.Sprintf("'%s' returns /etc/passwd contents for a traversal payload.", param),
			Boundary: "The server reads files outside the intended directory",
			Expected: "The parameter is confined to an allow-listed directory",
			Actual:   "An /etc/passwd body was returned",
			Impact:   "An unauthenticated request reads arbitrary files outside the web root.",
			Remedy: []string{
				"Resolve the path and confirm it stays within an allow-listed base directory",
				"Reject any path containing '..' or an absolute prefix",
			},
		}
	}
	return nil
}

func (c *Client) checkXSS(rawURL, param string, baseline Exchange) *Finding {
	payload := fmt.Sprintf(`'"><svg/onload=alert(%s)>`, marker)
	probe := c.capture("GET", mutate(rawURL, param, payload), fmt.Sprintf("HTML markup injected into '%s'", param), nil)
	sig := fmt.Sprintf(`<svg/onload=alert(%s)>`, marker)
	if probe.Err != "" || !isHTML(probe) || !strings.Contains(probe.RespBody, sig) {
		return nil
	}
	ev := &Evidence{Unauthenticated: true}
	ev.add(baseline)
	ev.add(probe)
	ev.Reproduced = 1 + c.verifyRepeat(probe, func(r Exchange) bool { return strings.Contains(r.RespBody, sig) }, 2)
	return &Finding{
		Host: hostOf(rawURL), Name: fmt.Sprintf("Reflected XSS in '%s'", param),
		Severity: "medium", Claimed: "medium", Source: "owasp", Confidence: "high",
		Evidence: ev, OWASP: "A03:2021 Injection", Endpoint: rawURL, Method: "GET", Param: param,
		Detail:   fmt.Sprintf("'%s' reflects < > \" ' into HTML unencoded.", param),
		Boundary: "Untrusted input reaches the HTML parser as markup",
		Expected: fmt.Sprintf("'%s' is HTML-encoded before being written to the page", param),
		Actual:   "The injected <svg onload=...> element is returned intact in an HTML response",
		Impact:   "A crafted link returns attacker-controlled markup that executes in the browser.",
		Remedy: []string{
			"Contextually HTML-encode all user input on output",
			"Add a Content-Security-Policy that forbids inline event handlers",
		},
	}
}

// exposedFile checks a single sensitive path and confirms it holds real
// credential material — a reachable but empty .env is not a finding.
var liveCredential = []*regexp.Regexp{
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`(?im)^\s*(DB_|DATABASE_|MYSQL_|POSTGRES_)?PASSWORD\s*=\s*\S+`),
	regexp.MustCompile(`(?im)^\s*AWS_SECRET_ACCESS_KEY\s*=\s*\S+`),
	regexp.MustCompile(`(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
}

func (c *Client) checkExposedFile(base, path, what string) *Finding {
	full := strings.TrimRight(base, "/") + path
	probe := c.capture("GET", full, "unauthenticated fetch of "+what, nil)
	if probe.Err != "" || probe.Status != 200 || probe.RespBody == "" {
		return nil
	}
	var hits []string
	for _, re := range liveCredential {
		if re.MatchString(probe.RespBody) {
			hits = append(hits, "credential material")
			break
		}
	}
	if len(hits) == 0 {
		return nil // reachable but nothing sensitive — not a finding
	}
	ev := &Evidence{Unauthenticated: true}
	ev.add(probe)
	ev.Reproduced = 1 + c.verifyRepeat(probe, func(r Exchange) bool {
		for _, re := range liveCredential {
			if re.MatchString(r.RespBody) {
				return true
			}
		}
		return false
	}, 2)
	return &Finding{
		Host: hostOf(full), Name: "Exposed " + what, Severity: "high", Claimed: "high",
		Source: "owasp", Confidence: "high", Evidence: ev, OWASP: "A05:2021 Security Misconfiguration",
		Endpoint: full, Method: "GET",
		Detail:   what + " is served to unauthenticated clients and contains live credentials.",
		Boundary: "Server-side configuration secrets are served to unauthenticated clients",
		Expected: "Deployment files are not reachable from the web root",
		Actual:   "HTTP 200 returning credential material",
		Impact:   "An unauthenticated request retrieves live credential material.",
		Remedy: []string{
			"Remove deployment files from the web root and block dotfile paths at the proxy",
			"Treat every exposed credential as compromised and rotate it now",
		},
	}
}

// atoiSafe is a small helper used by callers that pass numeric ids.
func atoiSafe(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil
}
