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
