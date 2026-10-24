package report

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MUKE-coder/scout/core"
)

// PrettyOptions tune the terminal report.
type PrettyOptions struct {
	Color   bool
	FixNext int // how many fix-next items to show; 0 means 5
}

// ANSI styles. The palette is chosen to stay readable on BOTH light and dark
// terminal backgrounds: mid-tone 256-colors, no near-white or near-black inks.
const (
	reset = "\x1b[0m"
	bold  = "\x1b[1m"

	accent = "\x1b[38;5;37m"  // teal — headers, logo, filled bars
	muted  = "\x1b[38;5;244m" // mid gray — metadata (reads on light and dark)
	faint  = "\x1b[38;5;240m" // darker gray — empty bar track
)

var sevColor = map[core.Severity]string{
	core.SeverityCritical: "\x1b[31m",       // red (legible on light and dark)
	core.SeverityHigh:     "\x1b[38;5;208m", // orange
	core.SeverityMedium:   "\x1b[38;5;178m", // gold
	core.SeverityLow:      "\x1b[38;5;33m",  // blue
	core.SeverityInfo:     muted,            // mid gray
}

var gradeColor = map[string]string{
	"A": "\x1b[38;5;34m", // green
	"B": "\x1b[38;5;34m",
	"C": "\x1b[38;5;178m", // gold
	"D": "\x1b[38;5;208m", // orange
	"F": "\x1b[31m",       // red
}

// scoutLogo is a FIGlet "Standard" wordmark, shown only in color (TTY) output.
var scoutLogo = []string{
	` ____   ____  ___  _   _ _____ `,
	`/ ___| / ___|/ _ \| | | |_   _|`,
	`\___ \| |   | | | | | | | | |  `,
	` ___) | |___| |_| | |_| | | |  `,
	`|____/ \____|\___/ \___/  |_|  `,
}

type painter bool

func (p painter) paint(style, s string) string {
	if !p || style == "" {
		return s
	}
	return style + s + reset
}

// cell colors text and pads it to width with plain spaces, so colored columns
// stay aligned (ANSI escapes would otherwise confuse a tabwriter's widths).
func (p painter) cell(style, text string, width int) string {
	pad := width - utf8.RuneCountInString(text)
	if pad < 0 {
		pad = 0
	}
	return p.paint(style, text) + strings.Repeat(" ", pad)
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

	// Logo + rule (color/TTY only; keeps piped output clean and tests exact).
	if p {
		for _, line := range scoutLogo {
			fmt.Fprintf(&b, "%s\n", p.paint(bold+accent, line))
		}
		fmt.Fprintf(&b, "%s\n\n", p.paint(muted, "see every way in · attack-surface scanner"))
	}

	// Header. This exact line (sans color) is part of the CLI's contract.
	fmt.Fprintf(&b, "%s  %s (%s)  mode %s\n", p.paint(bold, "Scout"), s.Target.Name, s.Target.Environment, s.Mode)
	fmt.Fprintf(&b, "%s\n", p.paint(muted, fmt.Sprintf("scan %s · %s · %d findings · %d skipped · %d errors",
		shortID(s.ID), duration(s), len(s.Findings), len(s.Skipped), len(s.Errors))))
	if line := stackLine(s.Target.Stack); line != "" {
		fmt.Fprintf(&b, "%s  %s\n", p.paint(muted, "stack"), p.paint(accent, line))
	}
	b.WriteString("\n")

	// Grade.
	if r.Report.Grade == "" {
		b.WriteString("Grade –  no checks ran, so nothing was assessed\n\n")
	} else {
		grade := p.paint(bold+gradeColor[r.Report.Grade], r.Report.Grade)
		fmt.Fprintf(&b, "Grade %s  %s\n", grade, p.paint(bold, fmt.Sprintf("%.1f / 100", r.Report.Score)))
		for _, c := range r.Report.Caps {
			fmt.Fprintf(&b, "  %s %s: %s (%s)\n", p.paint(muted, "capped at"), c.Grade, c.Reason, c.Title)
		}
		b.WriteString("\n")
		b.WriteString(p.paint(bold+accent, "Categories") + "\n")

		// Category subscores (manual columns so colored cells align).
		nameW := 0
		for _, c := range r.Report.Categories {
			if l := len(c.Category.String()); l > nameW {
				nameW = l
			}
		}
		for _, c := range r.Report.Categories {
			worst := ""
			if c.Findings > 0 {
				worst = fmt.Sprintf("%s · worst %s",
					p.paint(muted, fmt.Sprintf("%d open", c.Findings)),
					p.paint(sevColor[c.Worst], c.Worst.String()))
			}
			fmt.Fprintf(&b, "  %s  %s  %s  %s  %s\n",
				p.cell(accent, c.Category.String(), nameW),
				p.cell("", fmt.Sprintf("%5.1f", c.Score), 5),
				p.paint(bold+gradeColor[c.Grade], c.Grade),
				coloredBar(p, c.Score, 20, gradeColor[c.Grade]),
				worst)
		}
		b.WriteString("\n")
	}

	// Fix next.
	if len(r.FixNext) > 0 {
		b.WriteString(p.paint(bold+accent, "Fix next") + "\n")
		n := top
		if n > len(r.FixNext) {
			n = len(r.FixNext)
		}
		for i := 0; i < n; i++ {
			it := r.FixNext[i]
			fmt.Fprintf(&b, "  %s  %s  %s  %s  %s\n",
				p.paint(muted, fmt.Sprintf("%d.", i+1)),
				p.cell(accent, fmt.Sprintf("+%.1f pts", it.Points), 8),
				p.cell(muted, string(it.Effort), 2),
				p.paint(sevColor[it.Severity], it.Title),
				p.paint(muted, it.Asset))
		}
		b.WriteString("\n")
	}

	// Findings table (manual columns, colored severity).
	if len(s.Findings) == 0 {
		b.WriteString(p.paint(accent, "✓") + " No findings.\n")
	} else {
		fmt.Fprintf(&b, "%s %s\n", p.paint(bold+accent, "Findings"), p.paint(muted, fmt.Sprintf("(%d)", len(s.Findings))))
		sorted := SortFindings(s.Findings)
		catW, stW := len("category"), len("status")
		for _, f := range sorted {
			if l := len(f.Category.String()); l > catW {
				catW = l
			}
			if l := len(string(f.Status)); l > stW {
				stW = l
			}
		}
		// header row, dim
		fmt.Fprintf(&b, "  %s  %s  %s  %s\n",
			p.cell(muted, "SEVERITY", 8), p.cell(muted, "CATEGORY", catW),
			p.cell(muted, "STATUS", stW), p.paint(muted, "TITLE"))
		for _, f := range sorted {
			fmt.Fprintf(&b, "  %s  %s  %s  %s  %s\n",
				p.cell(sevColor[f.Severity], f.Severity.String(), 8),
				p.cell("", f.Category.String(), catW),
				p.cell(muted, string(f.Status), stW),
				f.Title,
				p.paint(muted, location(f)))
		}
	}

	// Skipped and errors, briefly.
	if len(s.Skipped) > 0 {
		fmt.Fprintf(&b, "\n%s %s\n", p.paint(bold, "Skipped"), p.paint(muted, fmt.Sprintf("(%d)", len(s.Skipped))))
		for _, sk := range s.Skipped {
			fmt.Fprintf(&b, "  %s  %s\n", sk.CheckID, p.paint(muted, sk.Reason))
		}
	}
	if len(s.Errors) > 0 {
		fmt.Fprintf(&b, "\n%s %s\n", p.paint(bold+sevColor[core.SeverityCritical], "Errors"), p.paint(muted, fmt.Sprintf("(%d)", len(s.Errors))))
		for _, e := range s.Errors {
			fmt.Fprintf(&b, "  %s  %s\n", e.CheckID, e.Error)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// stackLine renders the detected stack as "Next.js 16 · React · Go".
func stackLine(cs []core.StackComponent) string {
	if len(cs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		s := c.Name
		if c.Version != "" {
			s += " " + c.Version
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " · ")
}

func location(f core.Finding) string {
	if f.Location != "" {
		return f.Asset.Value + " (" + f.Location + ")"
	}
	return f.Asset.Value
}

// coloredBar draws a score bar: the filled part in color, the track dimmed.
func coloredBar(p painter, score float64, width int, color string) string {
	filled := int(score/100*float64(width) + 0.5)
	filled = max(0, min(width, filled))
	return p.paint(color, strings.Repeat("█", filled)) + p.paint(faint, strings.Repeat("░", width-filled))
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
