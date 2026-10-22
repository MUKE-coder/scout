package engine

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func TestPlanRunsNothing(t *testing.T) {
	var ran atomic.Int32
	count := func(context.Context, core.Target) ([]core.Finding, error) {
		ran.Add(1)
		return nil, nil
	}
	e := newEngine(t, Options{},
		check("a.passive", core.ModePassive, count),
		check("b.active", core.ModeActive, count),
	)
	target := core.Target{Name: "prod-site", URL: "https://example.com", Environment: core.EnvProd}
	p, err := e.Plan(Request{Target: target, Mode: core.ModeActive})
	if err != nil {
		t.Fatal(err)
	}
	if ran.Load() != 0 {
		t.Fatal("Plan executed checks")
	}
	if run, skipped := p.Counts(); run != 1 || skipped != 1 {
		t.Fatalf("counts = %d run, %d skipped", run, skipped)
	}
	if p.Effective != core.ModeSafe {
		t.Fatalf("effective = %v", p.Effective)
	}
}

func TestPlanMatchesRun(t *testing.T) {
	noop := func(context.Context, core.Target) ([]core.Finding, error) { return nil, nil }
	var checks []core.Check
	for _, m := range []core.Mode{core.ModePassive, core.ModeSafe, core.ModeActive, core.ModeIntrusive} {
		checks = append(checks, check("c."+m.String(), m, noop))
	}
	for _, env := range []core.Environment{core.EnvDev, core.EnvStaging, core.EnvProd} {
		for _, optIn := range []bool{false, true} {
			e := newEngine(t, Options{}, checks...)
			req := Request{Target: core.Target{Name: "t", URL: "http://localhost", Environment: env, AllowActive: optIn}, Mode: core.ModeIntrusive}
			p, _ := e.Plan(req)
			res, err := e.Run(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			skippedByRun := map[string]bool{}
			for _, s := range res.Skipped {
				skippedByRun[s.CheckID] = true
			}
			for _, entry := range p.Entries {
				if entry.Run == skippedByRun[entry.CheckID] {
					t.Errorf("%s optIn=%v: plan says run=%v for %s but Run disagreed", env, optIn, entry.Run, entry.CheckID)
				}
			}
			if p.Effective != res.Mode {
				t.Errorf("%s: plan effective %v != run mode %v", env, p.Effective, res.Mode)
			}
		}
	}
}

func TestPlanRender(t *testing.T) {
	e := newEngine(t, Options{},
		check("headers.csp", core.ModePassive, nil),
		check("app.inject", core.ModeActive, nil),
	)
	p, _ := e.Plan(Request{Target: core.Target{Name: "site", URL: "https://example.com", Environment: core.EnvProd}, Mode: core.ModeActive})
	var buf bytes.Buffer
	if err := p.Render(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"effective safe", "1 would run, 1 skipped", "Nothing was sent", "run     headers.csp", "skip    app.inject"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
}
