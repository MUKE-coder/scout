package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/scoring"
)

func sample() core.ScanResult {
	mk := func(id, title string, cat core.Category, sev core.Severity, effort core.Effort) core.Finding {
		f := core.Finding{
			CheckID: id, Title: title, Category: cat, Severity: sev, Confidence: core.ConfidenceConfirmed,
			Asset:       core.Asset{Kind: core.AssetURL, Value: "https://shop.example.com/", Host: "shop.example.com", Path: "/", Exposure: core.ExposureInternet},
			Remediation: core.Remediation{Effort: effort, What: "what " + title},
			CWE:         []string{"CWE-693"},
		}
		f.Normalize()
		return f
	}
	start := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	return core.ScanResult{
		ID:     "0123456789abcdef0123456789abcdef",
		Target: core.Target{Name: "https://shop.example.com", URL: "https://shop.example.com", Environment: core.EnvProd},
		Mode:   core.ModeSafe, StartedAt: start, FinishedAt: start.Add(1500 * time.Millisecond),
		Findings: []core.Finding{
			mk("headers.nosniff", "nosniff missing", core.CategoryHeaders, core.SeverityLow, core.EffortS),
			mk("app.injection", "Injection in search", core.CategoryApp, core.SeverityCritical, core.EffortM),
			mk("headers.csp", "CSP missing", core.CategoryHeaders, core.SeverityMedium, core.EffortM),
		},
		Skipped: []core.SkippedCheck{{CheckID: "app.active", Mode: core.ModeActive, Reason: "needs active mode; capped at safe"}},
	}
}

func build() Result {
	return Build(sample(), scoring.Options{Assessed: []core.Category{core.CategoryApp, core.CategoryHeaders}})
}

func TestPrettyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := Pretty(&buf, build(), PrettyOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Scout  https://shop.example.com (prod)  mode safe",
		"scan 0123456789ab · 1.5s · 3 findings · 1 skipped · 0 errors",
		"Grade F",
		"capped at F: confirmed critical finding (Injection in search)",
		"Categories",
		"Fix next",
		"1.  +",
		"Findings (3)",
		"Skipped (1)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colorless report contains ANSI codes")
	}
	// Findings are sorted worst first.
	crit := strings.Index(out, "critical  app")
	low := strings.Index(out, "low       headers")
	if crit < 0 || low < 0 || crit > low {
		t.Errorf("findings not sorted by severity:\n%s", out)
	}
}

func TestPrettyColor(t *testing.T) {
	var buf bytes.Buffer
	_ = Pretty(&buf, build(), PrettyOptions{Color: true})
	if !strings.Contains(buf.String(), "\x1b[31m") {
		t.Fatal("color report should color the F grade and critical findings red")
	}
}

func TestPrettyFixNextLimit(t *testing.T) {
	var buf bytes.Buffer
	_ = Pretty(&buf, build(), PrettyOptions{FixNext: 1})
	if strings.Contains(buf.String(), "2.  +") {
		t.Fatal("fix-next should be limited to 1 item")
	}
}

func TestPrettyEmpty(t *testing.T) {
	var buf bytes.Buffer
	s := sample()
	s.Findings, s.Skipped = nil, nil
	_ = Pretty(&buf, Build(s, scoring.Options{}), PrettyOptions{})
	if !strings.Contains(buf.String(), "No findings.") || !strings.Contains(buf.String(), "Grade A") {
		t.Fatalf("empty report:\n%s", buf.String())
	}
}

func TestPrettyNothingAssessed(t *testing.T) {
	var buf bytes.Buffer
	s := sample()
	s.Findings, s.Skipped, s.Assessed = nil, nil, []core.Category{}
	_ = Pretty(&buf, Build(s, scoring.Options{}), PrettyOptions{})
	out := buf.String()
	if !strings.Contains(out, "no checks ran") || strings.Contains(out, "Grade A") || strings.Contains(out, "Categories") {
		t.Fatalf("a scan with no checks must not look like a pass:\n%s", out)
	}
}
