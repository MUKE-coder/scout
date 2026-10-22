package engine

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

// modeChecks registers one check per mode, each counting its runs.
func modeChecks(t *testing.T) (*Engine, map[core.Mode]*atomic.Int32) {
	t.Helper()
	counts := map[core.Mode]*atomic.Int32{}
	var checks []core.Check
	for _, m := range []core.Mode{core.ModePassive, core.ModeSafe, core.ModeActive, core.ModeIntrusive} {
		n := &atomic.Int32{}
		counts[m] = n
		checks = append(checks, check("check."+m.String(), m, func(context.Context, core.Target) ([]core.Finding, error) {
			n.Add(1)
			return nil, nil
		}))
	}
	return newEngine(t, Options{}, checks...), counts
}

func TestModeCapping(t *testing.T) {
	cases := []struct {
		name      string
		env       core.Environment
		optIn     bool
		requested core.Mode
		wantRun   []core.Mode
	}{
		{"dev runs everything requested", core.EnvDev, false, core.ModeIntrusive,
			[]core.Mode{core.ModePassive, core.ModeSafe, core.ModeActive, core.ModeIntrusive}},
		{"dev respects a lower request", core.EnvDev, false, core.ModeSafe,
			[]core.Mode{core.ModePassive, core.ModeSafe}},
		{"staging caps at active", core.EnvStaging, false, core.ModeIntrusive,
			[]core.Mode{core.ModePassive, core.ModeSafe, core.ModeActive}},
		{"staging opt-in allows intrusive", core.EnvStaging, true, core.ModeIntrusive,
			[]core.Mode{core.ModePassive, core.ModeSafe, core.ModeActive, core.ModeIntrusive}},
		{"prod caps at safe", core.EnvProd, false, core.ModeIntrusive,
			[]core.Mode{core.ModePassive, core.ModeSafe}},
		{"prod opt-in allows active, never intrusive", core.EnvProd, true, core.ModeIntrusive,
			[]core.Mode{core.ModePassive, core.ModeSafe, core.ModeActive}},
		{"passive request runs only passive", core.EnvDev, false, core.ModePassive,
			[]core.Mode{core.ModePassive}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, counts := modeChecks(t)
			target := core.Target{Name: "t", URL: "http://localhost", Environment: c.env, AllowActive: c.optIn}
			res, err := e.Run(context.Background(), Request{Target: target, Mode: c.requested})
			if err != nil {
				t.Fatal(err)
			}
			want := map[core.Mode]bool{}
			for _, m := range c.wantRun {
				want[m] = true
			}
			for m, n := range counts {
				if ran := n.Load() == 1; ran != want[m] {
					t.Errorf("%s check ran=%v, want %v", m, ran, want[m])
				}
			}
			if got := len(res.Skipped); got != 4-len(c.wantRun) {
				t.Errorf("skipped = %d, want %d: %+v", got, 4-len(c.wantRun), res.Skipped)
			}
			for _, s := range res.Skipped {
				if s.Reason == "" || s.Mode <= res.Mode {
					t.Errorf("bad skip record: %+v (effective %v)", s, res.Mode)
				}
			}
		})
	}
}

func TestSkipReasonExplainsCap(t *testing.T) {
	e, _ := modeChecks(t)
	target := core.Target{Name: "t", URL: "https://example.com", Environment: core.EnvProd}
	res, _ := e.Run(context.Background(), Request{Target: target, Mode: core.ModeIntrusive})
	if res.Mode != core.ModeSafe {
		t.Fatalf("effective mode = %v", res.Mode)
	}
	for _, s := range res.Skipped {
		if !strings.Contains(s.Reason, "capped at safe") || !strings.Contains(s.Reason, "prod without per-target opt-in") {
			t.Errorf("unhelpful reason: %q", s.Reason)
		}
	}
}
