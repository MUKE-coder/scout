package engine

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
)

var localTarget = core.Target{Name: "local", URL: "http://localhost:8080", Environment: core.EnvDev}

func finding(title string) core.Finding {
	return core.Finding{Title: title, Severity: core.SeverityLow, Asset: core.Asset{Kind: core.AssetURL, Value: title}}
}

func check(id string, mode core.Mode, fn func(ctx context.Context, t core.Target) ([]core.Finding, error)) core.Check {
	return core.CheckFunc{CheckID: id, CheckMode: mode, CheckCategory: core.CategoryHeaders, Fn: fn}
}

func returns(titles ...string) func(context.Context, core.Target) ([]core.Finding, error) {
	return func(context.Context, core.Target) ([]core.Finding, error) {
		var out []core.Finding
		for _, t := range titles {
			out = append(out, finding(t))
		}
		return out, nil
	}
}

func newEngine(t *testing.T, opts Options, checks ...core.Check) *Engine {
	t.Helper()
	reg := core.NewRegistry()
	for _, c := range checks {
		reg.MustRegister(c)
	}
	return New(reg, opts)
}

func TestRunCollectsFindingsDeterministically(t *testing.T) {
	e := newEngine(t, Options{Concurrency: 3},
		check("c.three", core.ModePassive, returns("z")),
		check("a.one", core.ModePassive, returns("x", "y")),
		check("b.two", core.ModePassive, returns()),
	)
	res, err := e.Run(context.Background(), Request{Target: localTarget, Mode: core.ModePassive})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 3 || res.Findings[0].CheckID != "a.one" || res.Findings[2].CheckID != "c.three" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	for _, f := range res.Findings {
		if f.Fingerprint == "" || f.Status != core.StatusOpen {
			t.Fatalf("finding not normalized: %+v", f)
		}
	}
	if res.ID == "" || res.FinishedAt.Before(res.StartedAt) {
		t.Fatalf("bad scan metadata: %+v", res)
	}
}

func TestPanickingCheckDoesNotCrashScan(t *testing.T) {
	e := newEngine(t, Options{},
		check("boom", core.ModePassive, func(context.Context, core.Target) ([]core.Finding, error) {
			var m map[string]int
			m["x"]++ // nil map write panics
			return nil, nil
		}),
		check("fine", core.ModePassive, returns("ok")),
	)
	res, err := e.Run(context.Background(), Request{Target: localTarget})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].CheckID != "fine" {
		t.Fatalf("healthy check's findings lost: %+v", res.Findings)
	}
	if len(res.Errors) != 1 || res.Errors[0].CheckID != "boom" || !strings.Contains(res.Errors[0].Error, "panicked") {
		t.Fatalf("panic not recorded: %+v", res.Errors)
	}
}

func TestCheckTimeoutAbandonsStuckCheck(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	e := newEngine(t, Options{CheckTimeout: 50 * time.Millisecond},
		// Ignores its context entirely: the worst case.
		check("stuck", core.ModePassive, func(context.Context, core.Target) ([]core.Finding, error) {
			<-release
			return nil, nil
		}),
		check("fine", core.ModePassive, returns("ok")),
	)
	start := time.Now()
	res, _ := e.Run(context.Background(), Request{Target: localTarget})
	if time.Since(start) > 2*time.Second {
		t.Fatal("stuck check hung the scan")
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Error, ErrCheckTimeout.Error()) {
		t.Fatalf("timeout not recorded: %+v", res.Errors)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestCheckErrorRecorded(t *testing.T) {
	e := newEngine(t, Options{},
		check("err", core.ModePassive, func(context.Context, core.Target) ([]core.Finding, error) {
			return nil, errors.New("dns failed")
		}),
	)
	res, _ := e.Run(context.Background(), Request{Target: localTarget})
	if len(res.Errors) != 1 || res.Errors[0].Error != "dns failed" {
		t.Fatalf("errors = %+v", res.Errors)
	}
}

func TestCancellationStopsScan(t *testing.T) {
	var started atomic.Int32
	slow := func(ctx context.Context, _ core.Target) ([]core.Finding, error) {
		started.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var checks []core.Check
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		checks = append(checks, check(id, core.ModePassive, slow))
	}
	e := newEngine(t, Options{Concurrency: 2}, checks...)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	res, _ := e.Run(ctx, Request{Target: localTarget})
	if started.Load() > 4 {
		t.Fatalf("%d checks started after cancel; pool should stop feeding", started.Load())
	}
	last := res.Errors[len(res.Errors)-1]
	if last.CheckID != "engine" || !strings.Contains(last.Error, "cancelled") {
		t.Fatalf("cancellation not recorded: %+v", res.Errors)
	}
}

func TestConcurrencyBounded(t *testing.T) {
	var running, peak atomic.Int32
	fn := func(context.Context, core.Target) ([]core.Finding, error) {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		running.Add(-1)
		return nil, nil
	}
	var checks []core.Check
	for _, id := range []string{"a", "b", "c", "d", "e", "f"} {
		checks = append(checks, check(id, core.ModePassive, fn))
	}
	e := newEngine(t, Options{Concurrency: 2}, checks...)
	if _, err := e.Run(context.Background(), Request{Target: localTarget}); err != nil {
		t.Fatal(err)
	}
	if peak.Load() > 2 {
		t.Fatalf("peak concurrency = %d, want <= 2", peak.Load())
	}
}

func TestRestrictToCheckIDs(t *testing.T) {
	e := newEngine(t, Options{},
		check("a", core.ModePassive, returns("a")),
		check("b", core.ModePassive, returns("b")),
	)
	res, _ := e.Run(context.Background(), Request{Target: localTarget, Checks: []string{"b"}})
	if len(res.Findings) != 1 || res.Findings[0].CheckID != "b" {
		t.Fatalf("findings = %+v", res.Findings)
	}
}
