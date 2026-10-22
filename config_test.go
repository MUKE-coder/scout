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
	if _, err := NewConfig(WithEnvironment(core.EnvProd)); err == nil {
		t.Fatal("prod with default creds must be refused")
	}
	if _, err := NewConfig(WithEnvironment(core.EnvDev)); err != nil {
		t.Fatalf("dev with default creds should be allowed: %v", err)
	}
	c := DefaultConfig()
	c.Environment, c.Username, c.Password = core.EnvProd, "ops", "long-random-secret"
	if _, err := NewConfig(WithConfig(c)); err != nil {
		t.Fatalf("custom creds in prod: %v", err)
	}
}

func TestInvalidTargetRejected(t *testing.T) {
	if _, err := NewConfig(WithTarget("not a url")); err == nil {
		t.Fatal("expected invalid target error")
	}
}
