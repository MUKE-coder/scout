// Package report renders scan results: a terminal report, JSON, SARIF and
// diffs between scans. The CLI and the dashboard share it.
package report

import (
	"sort"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/scoring"
)

// Result bundles a scan with its score report and fix-next ranking.
type Result struct {
	Scan    core.ScanResult   `json:"scan"`
	Report  scoring.Report    `json:"report"`
	FixNext []scoring.FixItem `json:"fix_next"`
}

// Build scores a scan. Unless opts.Assessed is set, it uses the categories
// recorded on the scan, so the report grades exactly as the engine did.
func Build(scan core.ScanResult, opts scoring.Options) Result {
	if opts.Assessed == nil && scan.Assessed != nil {
		opts.Assessed = scan.Assessed
	}
	return Result{
		Scan:    scan,
		Report:  scoring.Score(scan.Findings, opts),
		FixNext: scoring.FixNext(scan.Findings, opts),
	}
}

// SortFindings orders findings worst first: severity, confidence, category,
// title, then fingerprint for stability.
func SortFindings(fs []core.Finding) []core.Finding {
	out := append([]core.Finding(nil), fs...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Severity != b.Severity:
			return a.Severity > b.Severity
		case a.Confidence != b.Confidence:
			return a.Confidence > b.Confidence
		case a.Category != b.Category:
			return a.Category < b.Category
		case a.Title != b.Title:
			return a.Title < b.Title
		}
		return a.Fingerprint < b.Fingerprint
	})
	return out
}
