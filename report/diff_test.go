package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func fp(id string, status core.Status) core.Finding {
	return core.Finding{Fingerprint: id, Title: id, Severity: core.SeverityMedium, Status: status}
}

func ids(fs []core.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Fingerprint)
	}
	return strings.Join(out, ",")
}

func TestDiffScans(t *testing.T) {
	a := core.ScanResult{ID: "a", Findings: []core.Finding{
		fp("stays", core.StatusOpen),
		fp("goes", core.StatusOpen),
		fp("was-fixed", core.StatusFixed),
		fp("was-accepted", core.StatusAcceptedRisk),
		fp("accepted-gone", core.StatusAcceptedRisk),
	}}
	b := core.ScanResult{ID: "b", Findings: []core.Finding{
		fp("stays", core.StatusOpen),
		fp("brand-new", core.StatusOpen),
		fp("was-fixed", core.StatusOpen),
		fp("was-accepted", core.StatusAcceptedRisk), // still accepted: ignored
		fp("came-back", core.StatusOpen),
	}}
	history := map[string]bool{"came-back": true}
	d := DiffScans(a, b, func(f string) bool { return history[f] })

	if got := ids(d.New); got != "brand-new" {
		t.Errorf("new = %s", got)
	}
	if got := ids(d.Regressed); got != "came-back,was-fixed" {
		t.Errorf("regressed = %s", got)
	}
	if got := ids(d.Fixed); got != "goes" {
		t.Errorf("fixed = %s (accepted findings that disappear are not fixes)", got)
	}
	if got := ids(d.Unchanged); got != "stays" {
		t.Errorf("unchanged = %s", got)
	}
}

func TestDiffWithoutHistory(t *testing.T) {
	d := DiffScans(core.ScanResult{}, core.ScanResult{Findings: []core.Finding{fp("x", core.StatusOpen)}}, nil)
	if ids(d.New) != "x" || len(d.Regressed) != 0 {
		t.Fatalf("diff = %+v", d)
	}
}

func TestPrettyDiff(t *testing.T) {
	d := DiffScans(
		core.ScanResult{ID: "aaaaaaaaaaaaaaaa", Findings: []core.Finding{fp("old", core.StatusOpen)}},
		core.ScanResult{ID: "bbbbbbbbbbbbbbbb", Findings: []core.Finding{fp("new", core.StatusOpen)}}, nil)
	var buf bytes.Buffer
	_ = PrettyDiff(&buf, d, false)
	out := buf.String()
	for _, want := range []string{"aaaaaaaaaaaa → bbbbbbbbbbbb", "1 new · 0 regressed · 1 fixed · 0 unchanged", "New (1)", "Fixed (1)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Regressed (") {
		t.Error("empty sections should be omitted")
	}
}
