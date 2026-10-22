package authz

import (
	"context"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func TestMetadataAndSafeNoop(t *testing.T) {
	ctx := core.WithScanCache(context.Background())
	target := core.Target{URL: "http://localhost:8080", Environment: core.EnvDev}
	seen := map[string]bool{}
	for _, c := range Checks() {
		if c.ID() == "" || seen[c.ID()] {
			t.Fatalf("bad or duplicate ID: %q", c.ID())
		}
		seen[c.ID()] = true
		if c.Category() != core.CategoryAuth {
			t.Errorf("%s: category = %v", c.ID(), c.Category())
		}
		got, err := c.Run(ctx, target)
		if err != nil || len(got) != 0 {
			t.Errorf("%s: skeleton Run should be a no-op, got %d findings, err %v", c.ID(), len(got), err)
		}
	}
}

func TestRemediationTemplatesPresent(t *testing.T) {
	for _, r := range []core.Remediation{RemediationJWT, RemediationIDOR, RemediationMissingAuth, RemediationCORS, RemediationMassAssignment} {
		if r.What == "" || r.Why == "" || len(r.How) == 0 || r.Effort == "" {
			t.Errorf("incomplete remediation template: %+v", r)
		}
	}
}
