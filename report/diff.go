package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/scoring"
)

// Diff is what changed between two scans, matched by fingerprint.
type Diff struct {
	From      string         `json:"from"`
	To        string         `json:"to"`
	New       []core.Finding `json:"new"`
	Regressed []core.Finding `json:"regressed"`
	Fixed     []core.Finding `json:"fixed"`
	Unchanged []core.Finding `json:"unchanged"`
}

// isOpen is the shared "needs attention" rule, including expired acceptances.
func isOpen(f core.Finding) bool { return scoring.Counts(f) }

// DiffScans compares scan a (before) with scan b (after). seenBefore
// reports whether a fingerprint appeared in any scan older than a; a finding
// that is back after being absent is a regression, not new. seenBefore may
// be nil.
func DiffScans(a, b core.ScanResult, seenBefore func(fingerprint string) bool) Diff {
	inA := map[string]core.Finding{}
	for _, f := range a.Findings {
		inA[f.Fingerprint] = f
	}
	inB := map[string]core.Finding{}
	for _, f := range b.Findings {
		inB[f.Fingerprint] = f
	}

	d := Diff{From: a.ID, To: b.ID}
	for _, f := range b.Findings {
		if !isOpen(f) {
			continue
		}
		prev, wasThere := inA[f.Fingerprint]
		switch {
		case wasThere && isOpen(prev):
			d.Unchanged = append(d.Unchanged, f)
		case wasThere && prev.Status == core.StatusFixed:
			d.Regressed = append(d.Regressed, f)
		case wasThere:
			// Accepted or false-positive in a, reopened in b: treat as new work.
			d.New = append(d.New, f)
		case seenBefore != nil && seenBefore(f.Fingerprint):
			d.Regressed = append(d.Regressed, f)
		default:
			d.New = append(d.New, f)
		}
	}
	for _, f := range a.Findings {
		if !isOpen(f) {
			continue
		}
		if after, ok := inB[f.Fingerprint]; !ok || after.Status == core.StatusFixed {
			d.Fixed = append(d.Fixed, f)
		}
	}
	d.New, d.Regressed = SortFindings(d.New), SortFindings(d.Regressed)
	d.Fixed, d.Unchanged = SortFindings(d.Fixed), SortFindings(d.Unchanged)
	return d
}

// PrettyDiff writes a diff for the terminal.
func PrettyDiff(w io.Writer, d Diff, color bool) error {
	p := painter(color)
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s → %s\n", p.paint(bold, "Scout diff"), shortID(d.From), shortID(d.To))
	fmt.Fprintf(&b, "%d new · %d regressed · %d fixed · %d unchanged\n",
		len(d.New), len(d.Regressed), len(d.Fixed), len(d.Unchanged))

	section := func(title string, fs []core.Finding) {
		if len(fs) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s (%d)\n", p.paint(bold, title), len(fs))
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		for _, f := range fs {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", p.paint(sevColor[f.Severity], f.Severity.String()), f.Category, f.Title, location(f))
		}
		_ = tw.Flush() // writes to a strings.Builder, which cannot fail
	}
	section("New", d.New)
	section("Regressed", d.Regressed)
	section("Fixed", d.Fixed)
	_, err := io.WriteString(w, b.String())
	return err
}
