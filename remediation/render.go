package remediation

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/MUKE-coder/scout/core"
)

var (
	serverHeader  = regexp.MustCompile(`(?im)^Server:\s*(.+)$`)
	poweredHeader = regexp.MustCompile(`(?im)^X-Powered-By:\s*(.+)$`)
)

// DetectStacks guesses the target's stack from a raw HTTP response and
// whether a Gin route table is available (scout.Mount). It returns stack
// names most specific first; empty means unknown.
func DetectStacks(response string, gin bool) []string {
	var out []string
	add := func(s string) {
		for _, x := range out {
			if x == s {
				return
			}
		}
		out = append(out, s)
	}
	if gin {
		add(Gin)
	}
	if m := poweredHeader.FindStringSubmatch(response); m != nil && strings.Contains(strings.ToLower(m[1]), "next.js") {
		add(NextJS)
	}
	if m := serverHeader.FindStringSubmatch(response); m != nil {
		s := strings.ToLower(m[1])
		switch {
		case strings.Contains(s, "nginx"):
			add(Nginx)
		case strings.Contains(s, "caddy"):
			add(Caddy)
		}
	}
	return out
}

// SelectFixes returns the fixes for the detected stacks in stack order. When
// none match (or stacks is empty) it returns every fix, so the user always
// sees something actionable.
func SelectFixes(fixes []core.Fix, stacks []string) []core.Fix {
	var out []core.Fix
	for _, s := range stacks {
		for _, f := range fixes {
			if f.Stack == s {
				out = append(out, f)
			}
		}
	}
	for _, f := range fixes {
		if f.Stack == Generic || f.Stack == "sentinel" {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return fixes
	}
	return out
}

// Render writes a finding's remediation as Markdown, tailored to stacks.
func Render(w io.Writer, f core.Finding, stacks []string) error {
	r := f.Remediation
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", f.Title)
	fmt.Fprintf(&b, "**Severity:** %s · **Confidence:** %s · **Effort:** %s\n", f.Severity, f.Confidence, effortLabel(r.Effort))
	if f.Asset.Value != "" {
		fmt.Fprintf(&b, "**Asset:** `%s`\n", f.Asset.Value)
	}
	b.WriteString("\n")
	if r.What != "" {
		fmt.Fprintf(&b, "### What\n\n%s\n\n", r.What)
	}
	if r.Why != "" {
		fmt.Fprintf(&b, "### Why it matters\n\n%s\n\n", r.Why)
	}
	if fixes := SelectFixes(r.How, stacks); len(fixes) > 0 {
		b.WriteString("### How to fix\n\n")
		for _, fx := range fixes {
			fmt.Fprintf(&b, "**%s**\n\n```%s\n%s\n```\n\n", stackLabel(fx.Stack), fx.Language, fx.Code)
			if fx.Note != "" {
				fmt.Fprintf(&b, "%s\n\n", fx.Note)
			}
		}
	}
	if len(f.CWE)+len(f.OWASP)+len(r.References) > 0 {
		b.WriteString("### References\n\n")
		for _, c := range f.CWE {
			fmt.Fprintf(&b, "- %s: https://cwe.mitre.org/data/definitions/%s.html\n", c, strings.TrimPrefix(c, "CWE-"))
		}
		for _, o := range f.OWASP {
			fmt.Fprintf(&b, "- OWASP %s\n", o)
		}
		for _, ref := range r.References {
			fmt.Fprintf(&b, "- %s\n", ref)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func effortLabel(e core.Effort) string {
	switch e {
	case core.EffortS:
		return "small"
	case core.EffortL:
		return "large"
	}
	return "medium"
}

func stackLabel(s string) string {
	switch s {
	case Gin:
		return "Gin"
	case Nginx:
		return "Nginx"
	case Caddy:
		return "Caddy"
	case NextJS:
		return "Next.js"
	case "sentinel":
		return "Sentinel"
	case Generic, "":
		return "Any stack"
	}
	return s
}
