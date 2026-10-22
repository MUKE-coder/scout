package scoring

import (
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func withFix(fd core.Finding, fp string, effort core.Effort) core.Finding {
	fd.Fingerprint, fd.Title = fp, fp
	fd.Remediation.Effort = effort
	return fd
}

func TestFixNextPrefersCheapBigWins(t *testing.T) {
	findings := []core.Finding{
		withFix(f(core.CategoryHeaders, core.SeverityLow), "header-low", core.EffortS),
		withFix(f(core.CategoryApp, core.SeverityCritical), "app-critical", core.EffortL),
		withFix(f(core.CategoryTLS, core.SeverityMedium), "tls-medium", core.EffortS),
	}
	items := FixNext(findings, Options{})
	if len(items) != 3 {
		t.Fatalf("items = %+v", items)
	}
	// The critical lifts an F cap: by far the most points, even at L effort.
	if items[0].Fingerprint != "app-critical" {
		t.Fatalf("first = %+v", items[0])
	}
	for i := 1; i < len(items); i++ {
		if items[i-1].Priority < items[i].Priority {
			t.Fatalf("not sorted by priority: %+v", items)
		}
	}
	for _, it := range items {
		if it.Points <= 0 {
			t.Errorf("%s regains no points: %+v", it.Fingerprint, it)
		}
	}
}

func TestFixNextEffortMatters(t *testing.T) {
	// Two identical findings; the cheaper fix ranks first.
	a := withFix(f(core.CategoryTLS, core.SeverityMedium), "a-large", core.EffortL)
	b := withFix(f(core.CategoryTLS, core.SeverityMedium), "b-small", core.EffortS)
	items := FixNext([]core.Finding{a, b}, Options{})
	if items[0].Fingerprint != "b-small" || items[0].Priority <= items[1].Priority {
		t.Fatalf("items = %+v", items)
	}
}

func TestFixNextSkipsClosedAndDefaultsEffort(t *testing.T) {
	closed := withFix(f(core.CategoryApp, core.SeverityHigh), "closed", core.EffortS)
	closed.Status = core.StatusFixed
	noEffort := withFix(f(core.CategoryApp, core.SeverityMedium), "no-effort", "")
	items := FixNext([]core.Finding{closed, noEffort}, Options{})
	if len(items) != 1 || items[0].Fingerprint != "no-effort" || items[0].Effort != core.EffortM {
		t.Fatalf("items = %+v", items)
	}
}

func TestFixNextDeterministic(t *testing.T) {
	findings := []core.Finding{
		withFix(f(core.CategoryHeaders, core.SeverityLow), "z", core.EffortS),
		withFix(f(core.CategoryHeaders, core.SeverityLow), "a", core.EffortS),
		withFix(f(core.CategoryHeaders, core.SeverityLow), "m", core.EffortS),
	}
	first := FixNext(findings, Options{})
	for range 20 {
		again := FixNext(findings, Options{})
		for i := range first {
			if first[i].Fingerprint != again[i].Fingerprint {
				t.Fatal("order changed between runs")
			}
		}
	}
	if first[0].Fingerprint != "a" {
		t.Fatalf("tie should break on fingerprint: %+v", first)
	}
}
