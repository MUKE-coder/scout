package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/remediation"
)

//go:embed report.html.tmpl
var reportTemplate string

// HTMLOptions configure the HTML report.
type HTMLOptions struct {
	Title     string
	Version   string
	Generated time.Time
	// FixNext limits the fix-next list per target (default 10).
	FixNext int
}

type htmlTarget struct {
	Result
	Stacks   []string
	Sections []htmlSection
	Top      int
}

type htmlSection struct {
	Severity core.Severity
	Findings []core.Finding
}

var funcs = template.FuncMap{
	"gradeClass": func(g string) string {
		switch g {
		case "A", "B":
			return "ok"
		case "C":
			return "medium"
		case "D":
			return "high"
		case "F":
			return "critical"
		}
		return "none"
	},
	"score": func(f float64) string { return fmt.Sprintf("%.1f", f) },
	"date":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"upper": strings.ToUpper,
	"title": func(s string) string {
		if s == "" {
			return s
		}
		return strings.ToUpper(s[:1]) + s[1:]
	},
	"fixes": remediation.SelectFixes,
	"inc":   func(i int) int { return i + 1 },
	"effort": func(e core.Effort) string {
		switch e {
		case core.EffortS:
			return "Small"
		case core.EffortL:
			return "Large"
		}
		return "Medium"
	},
	"cweURL": func(c string) string {
		return "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(c, "CWE-") + ".html"
	},
}

// HTML writes a self-contained, printable report for results. All text from
// scans is escaped by html/template.
func HTML(w io.Writer, results []Result, opts HTMLOptions) error {
	if opts.Title == "" {
		opts.Title = "Scout security report"
	}
	if opts.Generated.IsZero() {
		opts.Generated = time.Now()
	}
	top := opts.FixNext
	if top <= 0 {
		top = 10
	}
	tmpl, err := template.New("report").Funcs(funcs).Parse(reportTemplate)
	if err != nil {
		return err
	}
	var targets []htmlTarget
	for _, r := range results {
		t := htmlTarget{Result: r, Top: top}
		for _, f := range r.Scan.Findings {
			t.Stacks = remediation.DetectStacks(f.Evidence.Response, len(r.Scan.Target.Routes) > 0)
			if len(t.Stacks) > 0 {
				break
			}
		}
		if len(t.FixNext) > top {
			t.FixNext = t.FixNext[:top]
		}
		bySev := map[core.Severity][]core.Finding{}
		for _, f := range SortFindings(r.Scan.Findings) {
			if f.IsOpenAt(opts.Generated) {
				bySev[f.Severity] = append(bySev[f.Severity], f)
			}
		}
		for s := core.SeverityCritical; s >= core.SeverityInfo; s-- {
			if len(bySev[s]) > 0 {
				t.Sections = append(t.Sections, htmlSection{Severity: s, Findings: bySev[s]})
			}
		}
		targets = append(targets, t)
	}
	return tmpl.Execute(w, map[string]any{"Opts": opts, "Targets": targets})
}
