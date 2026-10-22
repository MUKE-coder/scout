package scoring

import (
	"math"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestRisk(t *testing.T) {
	cases := []struct {
		name string
		f    core.Finding
		want float64
	}{
		{"critical confirmed internet", core.Finding{Severity: core.SeverityCritical, Confidence: core.ConfidenceConfirmed,
			Asset: core.Asset{Exposure: core.ExposureInternet}}, 40},
		{"high likely authenticated", core.Finding{Severity: core.SeverityHigh, Confidence: core.ConfidenceLikely,
			Asset: core.Asset{Exposure: core.ExposureAuthenticated}}, 20 * 0.7 * 0.6},
		{"medium possible internal critical asset", core.Finding{Severity: core.SeverityMedium, Confidence: core.ConfidencePossible,
			Asset: core.Asset{Exposure: core.ExposureInternal, Criticality: 1.5}}, 8 * 0.4 * 0.4 * 1.5},
		{"unknown exposure counts as internet", core.Finding{Severity: core.SeverityLow, Confidence: core.ConfidenceConfirmed}, 2},
		{"info is free", core.Finding{Severity: core.SeverityInfo, Confidence: core.ConfidenceConfirmed}, 0},
	}
	for _, c := range cases {
		if got := Risk(c.f); !approx(got, c.want) {
			t.Errorf("%s: Risk = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCounts(t *testing.T) {
	for status, want := range map[core.Status]bool{
		"": true, core.StatusOpen: true,
		core.StatusFixed: false, core.StatusAcceptedRisk: false, core.StatusFalsePositive: false,
	} {
		if Counts(core.Finding{Status: status}) != want {
			t.Errorf("status %q: Counts = %v", status, !want)
		}
	}
}
