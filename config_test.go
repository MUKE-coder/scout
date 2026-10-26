package scout

import (
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func TestNewConfigOptions(t *testing.T) {
	c, err := NewConfig(
		WithEnvironment(core.EnvDev),
		WithTarget("http://localhost:8080"),
		WithMode(core.ModeActive),
		WithScope(Scope{Hosts: []string{"localhost"}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Targets) != 1 || c.Targets[0].Environment != core.EnvDev {
		t.Fatalf("targets = %+v", c.Targets)
	}
	if c.EffectiveMode() != core.ModeActive {
		t.Fatalf("dev should allow active, got %v", c.EffectiveMode())
	}
}

// From GitHub issue #8: WithRepo attaches a source path to targets that have
// none, but only in dev (a dashboard outside dev must not serve source).
func TestWithRepoDevOnly(t *testing.T) {
	dev, err := NewConfig(WithEnvironment(core.EnvDev), WithTarget("http://localhost:8080"), WithRepo("/src/app"))
	if err != nil {
		t.Fatal(err)
	}
	if dev.Targets[0].Repo != "/src/app" {
		t.Fatalf("dev target should get the repo, got %q", dev.Targets[0].Repo)
	}

	prod, err := NewConfig(WithEnvironment(core.EnvProd), WithTarget("https://app.example.com"), WithRepo("/src/app"))
	if err != nil {
		t.Fatal(err)
	}
	if prod.Targets[0].Repo != "" {
		t.Fatalf("prod target must not get the repo, got %q", prod.Targets[0].Repo)
	}

	// An explicit per-target repo is never overwritten.
	custom, err := NewConfig(WithEnvironment(core.EnvDev), WithRepo("/src/app"))
	if err != nil {
		t.Fatal(err)
	}
	custom.Targets = []core.Target{{Name: "x", URL: "http://x", Environment: core.EnvDev, Repo: "/explicit"}}
	custom.applyDefaults()
	if custom.Targets[0].Repo != "/explicit" {
		t.Fatalf("explicit repo overwritten: %q", custom.Targets[0].Repo)
	}
}

func TestEffectiveModeCappedInProd(t *testing.T) {
	c := DefaultConfig()
	c.Environment = core.EnvProd
	c.Mode = core.ModeIntrusive
	if got := c.EffectiveMode(); got != core.ModeSafe {
		t.Fatalf("prod effective mode = %v, want safe", got)
	}
}

func TestDefaultCredentialsRefusedOutsideDev(t *testing.T) {
	prod, err := NewConfig(WithEnvironment(core.EnvProd))
	if err != nil {
		t.Fatalf("a prod scan config needs no dashboard creds: %v", err)
	}
	if prod.ValidateDashboard() == nil {
		t.Fatal("prod dashboard with default creds must be refused")
	}
	if DefaultConfig().ValidateDashboard() != nil {
		t.Fatal("dev dashboard with default creds should be allowed")
	}
	c := DefaultConfig()
	c.Environment, c.Username, c.Password = core.EnvProd, "ops", "long-random-secret"
	if c.ValidateDashboard() != nil {
		t.Fatal("custom creds in prod should be allowed")
	}
}

func TestInvalidTargetRejected(t *testing.T) {
	if _, err := NewConfig(WithTarget("not a url")); err == nil {
		t.Fatal("expected invalid target error")
	}
}
