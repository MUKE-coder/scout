package dast

import (
	"context"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

// These checks are skeletons: metadata must be correct and Run must be a safe
// no-op until the probe logic is implemented.
func TestMetadataAndSafeNoop(t *testing.T) {
	ctx := core.WithScanCache(context.Background())
	target := core.Target{URL: "http://localhost:8080", Environment: core.EnvDev}
	seen := map[string]bool{}
	for _, c := range Checks() {
		if c.ID() == "" || seen[c.ID()] {
			t.Fatalf("bad or duplicate ID: %q", c.ID())
		}
		seen[c.ID()] = true
		if c.Category() != core.CategoryApp {
			t.Errorf("%s: category = %v", c.ID(), c.Category())
		}
		if c.Mode() < core.ModePassive || c.Mode() > core.ModeIntrusive {
			t.Errorf("%s: invalid mode", c.ID())
		}
		got, err := c.Run(ctx, target)
		if err != nil || len(got) != 0 {
			t.Errorf("%s: skeleton Run should be a no-op, got %d findings, err %v", c.ID(), len(got), err)
		}
	}
}

func TestRemediationTemplatesPresent(t *testing.T) {
	for _, r := range []core.Remediation{RemediationSQLi, RemediationCmdInjection, RemediationSSRF, RemediationPathTraversal, RemediationOpenRedirect, RemediationXSS} {
		if r.What == "" || r.Why == "" || len(r.How) == 0 || r.Effort == "" {
			t.Errorf("incomplete remediation template: %+v", r)
		}
	}
}
