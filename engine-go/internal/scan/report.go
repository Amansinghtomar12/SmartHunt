package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Export writes the results to a directory: the machine-readable JSON, and the
// one thing you actually submit — REPORT.md, the single triaged finding.
func Export(res *Results, outdir string) ([]string, error) {
	safe := strings.NewReplacer(".", "_", "*", "wildcard").Replace(res.Target)
	dir := filepath.Join(outdir, safe)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var written []string

	jsonPath := filepath.Join(dir, safe+".json")
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(jsonPath, data, 0o644); err != nil {
		return nil, err
	}
	written = append(written, jsonPath)

	if res.Report.Markdown != "" {
		repPath := filepath.Join(dir, safe+"-REPORT.md")
		if err := os.WriteFile(repPath, []byte(res.Report.Markdown), 0o644); err == nil {
			written = append(written, repPath)
		}
	}

	// A plain findings list, confirmed first, honestly labelled.
	var b strings.Builder
	b.WriteString("# SmartHunt findings — " + res.Target + "\n\n")
	b.WriteString("Only CONFIRMED rows carry captured proof. LEAD rows are unverified.\n\n")
	b.WriteString("| Status | Severity | Host | Finding | Source |\n|---|---|---|---|---|\n")
	for _, f := range res.Findings {
		status := "lead"
		sev := f.Severity
		if f.Proven {
			status = "**CONFIRMED**"
		} else {
			sev = "info (claimed " + f.Claimed + ")"
		}
		b.WriteString("| " + status + " | " + sev + " | " + f.Host + " | " +
			strings.ReplaceAll(f.Name, "|", "\\|") + " | " + f.Source + " |\n")
	}
	listPath := filepath.Join(dir, safe+"-findings.md")
	if err := os.WriteFile(listPath, []byte(b.String()), 0o644); err == nil {
		written = append(written, listPath)
	}
	return written, nil
}
