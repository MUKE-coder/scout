package report

import (
	"testing"

	"github.com/MUKE-coder/scout/core"
)

type mappedCheck struct {
	core.CheckFunc
	owasp, asvs []string
}

func (m mappedCheck) OWASP() []string { return m.owasp }
func (m mappedCheck) ASVS() []string  { return m.asvs }

func TestBuildCompliance(t *testing.T) {
	checks := []core.Check{
		mappedCheck{core.CheckFunc{CheckID: "a"}, []string{"A05:2021"}, []string{"V14.4.1", "V14.4.3"}},
		mappedCheck{core.CheckFunc{CheckID: "b"}, []string{"A05:2021", "A02:2021"}, []string{"V9.1.1"}},
		core.CheckFunc{CheckID: "unmapped"},
	}
	accepted := core.Finding{Severity: core.SeverityCritical, OWASP: []string{"A01:2021"}, Status: core.StatusAcceptedRisk}
	scans := []core.ScanResult{
		{Target: core.Target{Name: "shop"}, Findings: []core.Finding{
			{Severity: core.SeverityMedium, OWASP: []string{"A05:2021"}, Status: core.StatusOpen},
			{Severity: core.SeverityHigh, OWASP: []string{"A05:2021", "A05:2021"}, Status: core.StatusOpen},
			accepted,
		}},
		{Target: core.Target{Name: "blog"}},
	}
	c := BuildCompliance(scans, checks)

	if c.Mapped != 2 || c.Total != 3 || len(c.OWASP) != 10 || len(c.ASVS) != 14 {
		t.Fatalf("shape: mapped=%d total=%d owasp=%d asvs=%d", c.Mapped, c.Total, len(c.OWASP), len(c.ASVS))
	}
	if c.Targets[0] != "blog" || c.Targets[1] != "shop" {
		t.Fatalf("targets = %v", c.Targets)
	}
	a05 := c.OWASP[4]
	if a05.ID != "A05:2021" || a05.Checks != 2 {
		t.Fatalf("A05 = %+v", a05)
	}
	cell := a05.Targets["shop"]
	if cell.Open != 2 || cell.Worst == nil || *cell.Worst != core.SeverityHigh {
		t.Fatalf("A05/shop cell = %+v (duplicate tags must count once)", cell)
	}
	if c.OWASP[0].Targets["shop"].Open != 0 {
		t.Fatal("accepted-risk finding counted")
	}
	if c.ASVS[13].ID != "V14" || c.ASVS[13].Checks != 1 || c.ASVS[8].Checks != 1 {
		t.Fatalf("ASVS: V14=%+v V9=%+v (one check covering two V14 items counts once)", c.ASVS[13], c.ASVS[8])
	}
}
