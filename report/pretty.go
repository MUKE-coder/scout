package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/MUKE-coder/scout/core"
)

// PrettyOptions tune the terminal report.
type PrettyOptions struct {
	Color   bool
	FixNext int // how many fix-next items to show; 0 means 5
}

// ANSI styles. Color is used only for meaning: severity and grade.
const (
	reset = "\x1b[0m"
	bold  = "\x1b[1m"
	dim   = "\x1b[2m"
)

var sevColor = map[core.Severity]string{
	core.SeverityCritical: "\x1b[31m", // red
	core.SeverityHigh:     "\x1b[38;5;208m",
	core.SeverityMedium:   "\x1b[33m", // amber
	core.SeverityLow:      "\x1b[34m", // blue
	core.SeverityInfo:     "\x1b[90m", // gray
}

var gradeColor = map[string]string{
	"A": "\x1b[32m", "B": "\x1b[32m", "C": "\x1b[33m", "D": "\x1b[38;5;208m", "F": "\x1b[31m",
}

type painter bool

func (p painter) paint(style, s string) string {
	if !p || style == "" {
		return s
	}
	return style + s + reset
}

// Pretty writes the human-readable terminal report.
func Pretty(w io.Writer, r Result, opts PrettyOptions) error {
	p := painter(opts.Color)
	top := opts.FixNext
	if top <= 0 {
		top = 5
	}
	s := r.Scan
	var b strings.Builder

	// Header.
	fmt.Fprintf(&b, "%s  %s (%s)  mode %s\n", p.paint(bold, "Scout"), s.Target.Name, s.Target.Environment, s.Mode)
	fmt.Fprintf(&b, "%s\n\n", p.paint(dim, fmt.Sprintf("scan %s · %s · %d findings · %d skipped · %d errors",
		shortID(s.ID), duration(s), len(s.Findings), len(s.Skipped), len(s.Errors))))

	// Grade.
	if r.Report.Grade == "" {
		b.WriteString("Grade –  no checks ran, so nothing was assessed\n\n")
	} else {
		grade := p.paint(bold+gradeColor[r.Report.Grade], r.Report.Grade)
		fmt.Fprintf(&b, "Grade %s  %.1f / 100\n", grade, r.Report.Score)
		for _, c := range r.Report.Caps {
			fmt.Fprintf(&b, "  capped at %s: %s (%s)\n", c.Grade, c.Reason, c.Title)
		}
		b.WriteString("\n")
		b.WriteString(p.paint(bold, "Categories") + "\n")
	}

	// Category subscores.
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	for _, c := range r.Report.Categories {
		worst := ""
		if c.Findings > 0 {
			worst = fmt.Sprintf("%d open · worst %s", c.Findings, p.paint(sevColor[c.Worst], c.Worst.String()))
		}
		fmt.Fprintf(tw, "  %s\t%5.1f\t%s\t%s\t%s\n", c.Category, c.Score, c.Grade, bar(c.Score, 20), worst)
	}
	tw.Flush()
	b.WriteString("\n")

	// Fix next.
	if len(r.FixNext) > 0 {
		b.WriteString(p.paint(bold, "Fix next") + "\n")
		tw = tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		for i, it := range r.FixNext {
			if i == top {
				break
			}
			fmt.Fprintf(tw, "  %d.\t+%.1f pts\t%s\t%s\t%s\n", i+1, it.Points, it.Effort,
				p.paint(sevColor[it.Severity], it.Title), p.paint(dim, it.Asset))
		}
		tw.Flush()
		b.WriteString("\n")
	}

	// Findings table.
	if len(s.Findings) == 0 {
		b.WriteString("No findings.\n")
	} else {
		fmt.Fprintf(&b, "%s (%d)\n", p.paint(bold, "Findings"), len(s.Findings))
		tw = tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEVERITY\tCATEGORY\tSTATUS\tTITLE\tASSET")
		for _, f := range SortFindings(s.Findings) {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", p.paint(sevColor[f.Severity], f.Severity.String()),
				f.Category, f.Status, f.Title, location(f))
		}
		tw.Flush()
	}

	// Skipped and errors, briefly.
	if len(s.Skipped) > 0 {
		fmt.Fprintf(&b, "\n%s (%d)\n", p.paint(bold, "Skipped"), len(s.Skipped))
		for _, sk := range s.Skipped {
			fmt.Fprintf(&b, "  %s  %s\n", sk.CheckID, p.paint(dim, sk.Reason))
		}
	}
	if len(s.Errors) > 0 {
		fmt.Fprintf(&b, "\n%s (%d)\n", p.paint(bold, "Errors"), len(s.Errors))
		for _, e := range s.Errors {
			fmt.Fprintf(&b, "  %s  %s\n", e.CheckID, e.Error)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func location(f core.Finding) string {
	if f.Location != "" {
		return f.Asset.Value + " (" + f.Location + ")"
	}
	return f.Asset.Value
}

func bar(score float64, width int) string {
	filled := int(score/100*float64(width) + 0.5)
	filled = max(0, min(width, filled))
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func duration(s core.ScanResult) string {
	if s.FinishedAt.IsZero() || s.StartedAt.IsZero() {
		return "-"
	}
	return s.FinishedAt.Sub(s.StartedAt).Round(10 * time.Millisecond).String()
}
