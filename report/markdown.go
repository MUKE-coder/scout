package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/MUKE-coder/scout/core"
)

// Markdown writes a developer-facing report: a summary per target, then every
// open finding with evidence and concrete remediation — the thing you hand to
// an engineer to fix the vulnerabilities.
func Markdown(w io.Writer, results []Result) error {
	var b strings.Builder
	b.WriteString("# Scout security report\n\n")
	fmt.Fprintf(&b, "_Generated %s_\n\n", time.Now().UTC().Format("2006-01-02 15:04 UTC"))

	for _, r := range results {
		s := r.Scan
		fmt.Fprintf(&b, "## %s\n\n", mdEscape(s.Target.Name))
		fmt.Fprintf(&b, "**Grade %s** · %.1f / 100 · %d findings · mode %s\n\n",
			r.Report.Grade, r.Report.Score, len(s.Findings), s.Mode)

		findings := SortFindings(s.Findings)
		if len(findings) == 0 {
			b.WriteString("No findings. ✅\n\n")
			continue
		}

		// Summary table.
		b.WriteString("| Severity | Category | Title | Asset |\n")
		b.WriteString("|---|---|---|---|\n")
		for _, f := range findings {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				strings.ToUpper(f.Severity.String()), f.Category.String(),
				mdCell(f.Title), mdCell(assetText(f)))
		}
		b.WriteString("\n")

		// Detail per finding, with remediation.
		b.WriteString("### Findings in detail\n\n")
		for i, f := range findings {
			fmt.Fprintf(&b, "#### %d. %s\n\n", i+1, mdEscape(f.Title))
			fmt.Fprintf(&b, "- **Severity:** %s  ", strings.ToUpper(f.Severity.String()))
			fmt.Fprintf(&b, "**Confidence:** %s  ", f.Confidence.String())
			fmt.Fprintf(&b, "**Category:** %s\n", f.Category.String())
			fmt.Fprintf(&b, "- **Asset:** `%s`\n", assetText(f))
			if tags := stdTags(f); tags != "" {
				fmt.Fprintf(&b, "- **Standards:** %s\n", tags)
			}
			if f.Evidence.Matched != "" {
				fmt.Fprintf(&b, "- **Evidence:** %s\n", mdEscape(f.Evidence.Matched))
			}
			if f.Evidence.Notes != "" {
				fmt.Fprintf(&b, "- **Notes:** %s\n", mdEscape(f.Evidence.Notes))
			}
			b.WriteString("\n")

			rem := f.Remediation
			if rem.What != "" {
				fmt.Fprintf(&b, "**What:** %s\n\n", mdEscape(rem.What))
			}
			if rem.Why != "" {
				fmt.Fprintf(&b, "**Why it matters:** %s\n\n", mdEscape(rem.Why))
			}
			if len(rem.How) > 0 {
				b.WriteString("**How to fix:**\n\n")
				for _, fix := range rem.How {
					if fix.Stack != "" && fix.Stack != "generic" {
						fmt.Fprintf(&b, "_%s:_\n\n", fix.Stack)
					}
					lang := fix.Language
					if lang == "" {
						lang = "text"
					}
					fmt.Fprintf(&b, "```%s\n%s\n```\n\n", lang, strings.TrimRight(fix.Code, "\n"))
				}
			}
			if len(rem.References) > 0 {
				b.WriteString("**References:** ")
				for j, ref := range rem.References {
					if j > 0 {
						b.WriteString(" · ")
					}
					fmt.Fprintf(&b, "<%s>", ref)
				}
				b.WriteString("\n\n")
			}
			b.WriteString("---\n\n")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Text writes a plain-text version of the developer report (no Markdown
// syntax), for pasting into a ticket or email.
func Text(w io.Writer, results []Result) error {
	var b strings.Builder
	rule := strings.Repeat("=", 64)
	b.WriteString("SCOUT SECURITY REPORT\n")
	fmt.Fprintf(&b, "Generated %s\n\n", time.Now().UTC().Format("2006-01-02 15:04 UTC"))

	for _, r := range results {
		s := r.Scan
		b.WriteString(rule + "\n")
		fmt.Fprintf(&b, "%s\n", s.Target.Name)
		fmt.Fprintf(&b, "Grade %s · %.1f/100 · %d findings · mode %s\n", r.Report.Grade, r.Report.Score, len(s.Findings), s.Mode)
		b.WriteString(rule + "\n\n")

		findings := SortFindings(s.Findings)
		if len(findings) == 0 {
			b.WriteString("No findings.\n\n")
			continue
		}
		for i, f := range findings {
			fmt.Fprintf(&b, "%d. [%s] %s\n", i+1, strings.ToUpper(f.Severity.String()), f.Title)
			fmt.Fprintf(&b, "   Asset: %s\n", assetText(f))
			if tags := stdTags(f); tags != "" {
				fmt.Fprintf(&b, "   Standards: %s\n", tags)
			}
			if f.Evidence.Matched != "" {
				fmt.Fprintf(&b, "   Evidence: %s\n", f.Evidence.Matched)
			}
			if f.Remediation.What != "" {
				fmt.Fprintf(&b, "   What: %s\n", f.Remediation.What)
			}
			if f.Remediation.Why != "" {
				fmt.Fprintf(&b, "   Why:  %s\n", f.Remediation.Why)
			}
			for _, fix := range f.Remediation.How {
				fmt.Fprintf(&b, "   Fix:  %s\n", strings.ReplaceAll(strings.TrimRight(fix.Code, "\n"), "\n", "\n         "))
			}
			b.WriteString("\n")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func assetText(f core.Finding) string {
	if f.Location != "" && f.Location != f.Asset.Value {
		return f.Asset.Value + " (" + f.Location + ")"
	}
	return f.Asset.Value
}

func stdTags(f core.Finding) string {
	parts := make([]string, 0, len(f.CWE)+len(f.OWASP))
	parts = append(parts, f.CWE...)
	parts = append(parts, f.OWASP...)
	return strings.Join(parts, ", ")
}

// mdEscape neutralizes characters that would break Markdown structure.
func mdEscape(s string) string {
	r := strings.NewReplacer("|", "\\|", "`", "'", "\r", "", "\n", " ")
	return r.Replace(s)
}

// mdCell is mdEscape for a table cell (also trims to keep tables readable).
func mdCell(s string) string {
	s = mdEscape(s)
	if len(s) > 80 {
		s = s[:77] + "…"
	}
	return s
}
