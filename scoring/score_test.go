package scoring

import (
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func f(cat core.Category, sev core.Severity) core.Finding {
	return core.Finding{Category: cat, Severity: sev, Confidence: core.ConfidenceConfirmed,
		Asset: core.Asset{Exposure: core.ExposureInternet}, Status: core.StatusOpen}
}

func TestGrade(t *testing.T) {
	for score, want := range map[float64]string{100: "A", 90: "A", 89.9: "B", 80: "B", 70: "C", 60: "D", 59.9: "F", 0: "F"} {
		if got := Grade(score); got != want {
			t.Errorf("Grade(%v) = %s, want %s", score, got, want)
		}
	}
}

func TestNoFindingsScoresPerfect(t *testing.T) {
	r := Score(nil, Options{})
	if r.Score != 100 || r.Grade != "A" || len(r.Categories) != len(DefaultWeights) {
		t.Fatalf("report = %+v", r)
	}
}

func TestDecayValues(t *testing.T) {
	only := Options{Assessed: []core.Category{core.CategoryApp}}
	cases := map[core.Severity]float64{
		core.SeverityCritical: 44.9,
		core.SeverityHigh:     67.0,
		core.SeverityMedium:   85.2,
		core.SeverityLow:      96.1,
		core.SeverityInfo:     100,
	}
	for sev, want := range cases {
		r := Score([]core.Finding{f(core.CategoryApp, sev)}, only)
		if r.Categories[0].Score != want {
			t.Errorf("%s: score = %v, want %v", sev, r.Categories[0].Score, want)
		}
	}
}

func TestScoreNeverNegative(t *testing.T) {
	var many []core.Finding
	for range 500 {
		many = append(many, f(core.CategoryApp, core.SeverityCritical))
	}
	r := Score(many, Options{Assessed: []core.Category{core.CategoryApp}})
	if r.Score < 0 || r.Categories[0].Score < 0 {
		t.Fatalf("negative score: %+v", r)
	}
}

func TestManyLowsDoNotOutweighOneCritical(t *testing.T) {
	var lows []core.Finding
	for range 8 { // every header check failing
		lows = append(lows, f(core.CategoryHeaders, core.SeverityLow))
	}
	headersOnly := Score(lows, Options{})
	oneCritical := Score([]core.Finding{f(core.CategoryApp, core.SeverityCritical)}, Options{})
	if headersOnly.Score <= oneCritical.Score {
		t.Fatalf("8 header lows (%v) scored worse than one app critical (%v)", headersOnly.Score, oneCritical.Score)
	}
}

func TestOnlyOpenFindingsCount(t *testing.T) {
	accepted := f(core.CategoryApp, core.SeverityCritical)
	accepted.Status = core.StatusAcceptedRisk
	r := Score([]core.Finding{accepted}, Options{})
	if r.Score != 100 {
		t.Fatalf("accepted-risk finding affected score: %v", r.Score)
	}
}

func TestCategorySubscores(t *testing.T) {
	r := Score([]core.Finding{
		f(core.CategoryTLS, core.SeverityMedium),
		f(core.CategoryTLS, core.SeverityLow),
	}, Options{Assessed: []core.Category{core.CategoryTLS, core.CategoryHeaders}})
	if len(r.Categories) != 2 {
		t.Fatalf("categories = %+v", r.Categories)
	}
	tls := r.Categories[0]
	if tls.Category != core.CategoryTLS || tls.Findings != 2 || tls.Worst != core.SeverityMedium || tls.Risk != 10 {
		t.Fatalf("tls = %+v", tls)
	}
	if r.Categories[1].Score != 100 || r.Categories[1].Grade != "A" {
		t.Fatalf("headers = %+v", r.Categories[1])
	}
}

func TestAppWeightedAboveHeaders(t *testing.T) {
	opts := Options{Assessed: []core.Category{core.CategoryApp, core.CategoryHeaders}}
	app := Score([]core.Finding{f(core.CategoryApp, core.SeverityMedium)}, opts)
	hdr := Score([]core.Finding{f(core.CategoryHeaders, core.SeverityMedium)}, opts)
	if app.Score >= hdr.Score {
		t.Fatalf("app medium (%v) should cost more than headers medium (%v)", app.Score, hdr.Score)
	}
}
