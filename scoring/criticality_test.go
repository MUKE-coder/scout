package scoring

import (
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func TestCriticalityRules(t *testing.T) {
	opts := Options{Criticality: []CriticalityRule{
		{Host: "api.example.com", PathPrefix: "/payments", Value: 1.5},
		{Host: "*.example.com", Value: 1.2},
		{Host: "www.example.com", Value: 0.7}, // shadowed by the wildcard above: first match wins
	}}
	cases := []struct {
		asset core.Asset
		want  float64
	}{
		{core.Asset{Host: "api.example.com", Path: "/payments/charge"}, 1.5},
		{core.Asset{Host: "api.example.com", Path: "/users"}, 1.2},
		{core.Asset{Host: "www.example.com", Path: "/"}, 1.2},
		{core.Asset{Host: "other.org", Path: "/"}, 1.0},
		{core.Asset{Host: "api.example.com", Path: "/payments", Criticality: 0.5}, 0.5}, // asset value wins
	}
	for _, c := range cases {
		if got := opts.criticality(c.asset); got != c.want {
			t.Errorf("%s%s: criticality = %v, want %v", c.asset.Host, c.asset.Path, got, c.want)
		}
	}
}

func TestCriticalityAffectsScore(t *testing.T) {
	fd := f(core.CategoryApp, core.SeverityMedium)
	fd.Asset.Host, fd.Asset.Path = "pay.example.com", "/"
	only := []core.Category{core.CategoryApp}

	plain := Score([]core.Finding{fd}, Options{Assessed: only})
	critical := Score([]core.Finding{fd}, Options{Assessed: only,
		Criticality: []CriticalityRule{{Host: "pay.example.com", Value: 1.5}}})
	marketing := Score([]core.Finding{fd}, Options{Assessed: only,
		Criticality: []CriticalityRule{{Host: "pay.example.com", Value: 0.7}}})

	if !(critical.Score < plain.Score && plain.Score < marketing.Score) {
		t.Fatalf("criticality not applied: critical %v, plain %v, marketing %v", critical.Score, plain.Score, marketing.Score)
	}
}
