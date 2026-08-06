package scan

import "testing"

func withEvidence() *Evidence {
	ev := &Evidence{Unauthenticated: true, Reproduced: 3}
	ev.add(Exchange{Method: "GET", URL: "https://t.com/u?id=1", Status: 500,
		RespBody: "SQL syntax error near", Note: "quote injected"})
	return ev
}

// The whole false-positive fix in one test: unverified leads must never be shown
// as critical/high, and evidence-backed findings must keep their grade.
func TestClassifyConfidence(t *testing.T) {
	cases := []struct {
		f          Finding
		wantProven bool
		wantShown  string
	}{
		{Finding{Name: "Possible CVE-2021-41773", Severity: "critical", Source: "cve", Confidence: "low"}, false, "info"},
		{Finding{Name: "Secret in JS: Stripe live key", Severity: "critical", Source: "jsrecon", Confidence: "low"}, false, "info"},
		{Finding{Name: "nuclei template", Severity: "critical", Source: "nuclei", Confidence: "low"}, false, "info"},
		{Finding{Name: "Possible subdomain takeover", Severity: "high", Source: "builtin"}, false, "info"},
		{Finding{Name: "SQL injection (MySQL) in 'id'", Severity: "critical", Source: "owasp", Confidence: "high", Evidence: withEvidence()}, true, "critical"},
		{Finding{Name: "Broken access control (IDOR)", Severity: "high", Source: "accesscontrol", Confidence: "high", Evidence: withEvidence()}, true, "high"},
		// evidence present but confidence not high -> still a lead
		{Finding{Name: "Maybe something", Severity: "high", Source: "owasp", Confidence: "medium", Evidence: withEvidence()}, false, "info"},
	}
	for _, c := range cases {
		proven, shown := classifyConfidence(&c.f)
		if proven != c.wantProven || shown != c.wantShown {
			t.Errorf("%s: got (proven=%v shown=%s), want (proven=%v shown=%s)",
				c.f.Name, proven, shown, c.wantProven, c.wantShown)
		}
	}
}

func TestBuildReportPicksProvenAndDropsLeads(t *testing.T) {
	findings := []*Finding{
		{Name: "Possible CVE-2021-41773", Severity: "critical", Source: "cve", Confidence: "low"},
		{Name: "Secret in JS: Stripe live key", Severity: "critical", Source: "jsrecon", Confidence: "low"},
		{Name: "SQL injection (MySQL) in 'id'", Severity: "critical", Source: "owasp",
			Confidence: "high", Endpoint: "https://t.com/u?id=1", Evidence: withEvidence(),
			Impact: "x", Boundary: "b", Expected: "e", Actual: "a", Remedy: []string{"fix"}},
	}
	r := buildReport(findings, "t.com")
	if r.Kind != "report" {
		t.Fatalf("kind = %q, want report", r.Kind)
	}
	if r.Finding.Source != "owasp" {
		t.Errorf("picked %q, want the evidence-backed owasp finding", r.Finding.Source)
	}
	if r.Severity != "high" { // SQLi locks to high, not critical
		t.Errorf("severity = %q, want high (locked)", r.Severity)
	}
	if r.Dropped != 2 {
		t.Errorf("dropped = %d, want 2 (both unverified leads)", r.Dropped)
	}
}

func TestBuildReportNoneWhenOnlyLeads(t *testing.T) {
	findings := []*Finding{
		{Name: "Possible CVE-2021-41773", Severity: "critical", Source: "cve", Confidence: "low"},
		{Name: "Secret in JS: aws", Severity: "high", Source: "jsrecon", Confidence: "low"},
	}
	r := buildReport(findings, "t.com")
	if r.Kind != "none" {
		t.Errorf("kind = %q, want none — leads alone are not reportable", r.Kind)
	}
}

func TestMaskHidesCredentials(t *testing.T) {
	in := `DB_PASSWORD=hunter2 and key AKIAIOSFODNN7EXAMPLE and {"password":"s3cr3t"}`
	out := mask(in)
	for _, leaked := range []string{"hunter2", "AKIAIOSFODNN7EXAMPLE", "s3cr3t"} {
		if contains(out, leaked) {
			t.Errorf("mask leaked %q: %s", leaked, out)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
