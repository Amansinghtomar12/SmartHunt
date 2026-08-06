package scan

// Finding is a potential issue. The fields below Source are what separate a
// scanner hit from something a triager can act on; a check that cannot fill
// them leaves them empty, and triage refuses to promote the finding rather than
// dress it up.
type Finding struct {
	Host       string    `json:"host"`
	Name       string    `json:"name"`
	Severity   string    `json:"severity"` // as the display shows it (honest)
	Claimed    string    `json:"severity_claimed"`
	Proven     bool      `json:"proven"`
	Detail     string    `json:"detail,omitempty"`
	Source     string    `json:"source,omitempty"`
	OWASP      string    `json:"owasp,omitempty"`
	Endpoint   string    `json:"endpoint,omitempty"`
	Method     string    `json:"method,omitempty"`
	Param      string    `json:"param,omitempty"`
	Boundary   string    `json:"boundary,omitempty"`
	Expected   string    `json:"expected,omitempty"`
	Actual     string    `json:"actual,omitempty"`
	Impact     string    `json:"impact,omitempty"`
	Confidence string    `json:"confidence,omitempty"`
	Remedy     []string  `json:"remediation,omitempty"`
	Evidence   *Evidence `json:"evidence,omitempty"`
}

var severityRank = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5,
}
