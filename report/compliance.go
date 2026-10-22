package report

import (
	"sort"
	"strings"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/scoring"
)

// Standard categories used by the compliance view.
var (
	OWASPTop10 = []struct{ ID, Name string }{
		{"A01:2021", "Broken access control"},
		{"A02:2021", "Cryptographic failures"},
		{"A03:2021", "Injection"},
		{"A04:2021", "Insecure design"},
		{"A05:2021", "Security misconfiguration"},
		{"A06:2021", "Vulnerable and outdated components"},
		{"A07:2021", "Identification and authentication failures"},
		{"A08:2021", "Software and data integrity failures"},
		{"A09:2021", "Security logging and monitoring failures"},
		{"A10:2021", "Server-side request forgery"},
	}
	ASVSChapters = []struct{ ID, Name string }{
		{"V1", "Architecture, design and threat modeling"},
		{"V2", "Authentication"},
		{"V3", "Session management"},
		{"V4", "Access control"},
		{"V5", "Validation, sanitization and encoding"},
		{"V6", "Stored cryptography"},
		{"V7", "Error handling and logging"},
		{"V8", "Data protection"},
		{"V9", "Communication"},
		{"V10", "Malicious code"},
		{"V11", "Business logic"},
		{"V12", "Files and resources"},
		{"V13", "API and web service"},
		{"V14", "Configuration"},
	}
)

// Cell is one target's open findings in one category.
type Cell struct {
	Open  int            `json:"open"`
	Worst *core.Severity `json:"worst,omitempty"`
}

// ComplianceRow is one standard category: how many checks cover it and the
// open findings per target.
type ComplianceRow struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Checks  int             `json:"checks"`
	Targets map[string]Cell `json:"targets,omitempty"`
}

// Compliance is the OWASP Top 10 heatmap plus ASVS chapter coverage.
type Compliance struct {
	Targets []string        `json:"targets"`
	OWASP   []ComplianceRow `json:"owasp"`
	ASVS    []ComplianceRow `json:"asvs"`
	// Mapped is how many registered checks declare standards mappings.
	Mapped int `json:"mapped"`
	Total  int `json:"total"`
}

// BuildCompliance maps open findings (by their OWASP tags) and registered
// checks (by StandardsMapper) onto OWASP Top 10 and ASVS chapters.
func BuildCompliance(scans []core.ScanResult, checks []core.Check) Compliance {
	owaspChecks := map[string]int{}
	asvsChecks := map[string]int{}
	mapped := 0
	for _, c := range checks {
		m, ok := c.(core.StandardsMapper)
		if !ok {
			continue
		}
		mapped++
		for _, id := range uniq(m.OWASP()) {
			owaspChecks[id]++
		}
		chapters := map[string]bool{}
		for _, id := range m.ASVS() {
			chapters[asvsChapter(id)] = true
		}
		for ch := range chapters {
			asvsChecks[ch]++
		}
	}

	out := Compliance{Mapped: mapped, Total: len(checks), Targets: []string{}}
	cells := map[string]map[string]Cell{} // owasp id -> target -> cell
	for _, sc := range scans {
		out.Targets = append(out.Targets, sc.Target.Name)
		for _, f := range sc.Findings {
			if !scoring.Counts(f) {
				continue
			}
			for _, id := range uniq(f.OWASP) {
				if cells[id] == nil {
					cells[id] = map[string]Cell{}
				}
				cell := cells[id][sc.Target.Name]
				cell.Open++
				if cell.Worst == nil || f.Severity > *cell.Worst {
					s := f.Severity
					cell.Worst = &s
				}
				cells[id][sc.Target.Name] = cell
			}
		}
	}
	sort.Strings(out.Targets)
	for _, c := range OWASPTop10 {
		out.OWASP = append(out.OWASP, ComplianceRow{ID: c.ID, Name: c.Name, Checks: owaspChecks[c.ID], Targets: cells[c.ID]})
	}
	for _, c := range ASVSChapters {
		out.ASVS = append(out.ASVS, ComplianceRow{ID: c.ID, Name: c.Name, Checks: asvsChecks[c.ID]})
	}
	return out
}

// asvsChapter turns "V14.4.1" or "v14" into "V14".
func asvsChapter(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if i := strings.IndexByte(id, '.'); i > 0 {
		id = id[:i]
	}
	return id
}

func uniq(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
