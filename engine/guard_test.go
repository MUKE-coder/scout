package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/selftest"
)

// getCheck fetches path on the target through the scan's guarded client and
// records the error, if any.
func getCheck(id, rawURL string, got *error) core.Check {
	return check(id, core.ModePassive, func(ctx context.Context, _ core.Target) ([]core.Finding, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := core.HTTPClient(ctx).Do(req)
		if err == nil {
			resp.Body.Close()
		}
		*got = err
		return nil, nil
	})
}

func testServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestGuardAllowsTargetHostByDefault(t *testing.T) {
	srv, hits := testServer(t)
	var err error
	e := newEngine(t, Options{}, getCheck("get", srv.URL+"/", &err))
	target := core.Target{Name: "t", URL: srv.URL, Environment: core.EnvDev}
	if _, runErr := e.Run(context.Background(), Request{Target: target}); runErr != nil {
		t.Fatal(runErr)
	}
	if err != nil || hits.Load() != 1 {
		t.Fatalf("in-scope request failed: err=%v hits=%d", err, hits.Load())
	}
}

func TestEveryRequestCarriesSignedHeader(t *testing.T) {
	key := []byte("shared-with-sentinel-0123456789ab")
	var verified, total atomic.Int32
	var lastScan atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		total.Add(1)
		if info, err := selftest.Verify(r, key, time.Now(), 0); err == nil {
			verified.Add(1)
			lastScan.Store(info.ScanID)
		}
	}))
	defer srv.Close()

	var errs [3]error
	e := newEngine(t, Options{SigningKey: key},
		getCheck("a", srv.URL+"/", &errs[0]),
		getCheck("b", srv.URL+"/api?x=1", &errs[1]),
		getCheck("c", srv.URL+"/deep/path", &errs[2]),
	)
	res, err := e.Run(context.Background(), Request{Target: core.Target{Name: "t", URL: srv.URL, Environment: core.EnvDev}})
	if err != nil {
		t.Fatal(err)
	}
	if total.Load() != 3 || verified.Load() != 3 {
		t.Fatalf("verified %d of %d requests", verified.Load(), total.Load())
	}
	if lastScan.Load() != res.ID {
		t.Fatalf("header scan id %v != scan %s", lastScan.Load(), res.ID)
	}
}

func TestGuardRefusesOutOfScope(t *testing.T) {
	srv, hits := testServer(t)
	var err error
	// The target is localhost; the check tries a different host.
	e := newEngine(t, Options{}, getCheck("get", "http://other.invalid/", &err))
	target := core.Target{Name: "t", URL: srv.URL, Environment: core.EnvDev}
	_, _ = e.Run(context.Background(), Request{Target: target})
	if !errors.Is(err, ErrOutOfScope) || hits.Load() != 0 {
		t.Fatalf("out-of-scope request not refused: err=%v hits=%d", err, hits.Load())
	}
}

func TestGuardExcludedPath(t *testing.T) {
	srv, hits := testServer(t)
	var err error
	e := newEngine(t, Options{Scope: core.Scope{ExcludePaths: []string{"/admin"}}},
		getCheck("get", srv.URL+"/admin/users", &err))
	target := core.Target{Name: "t", URL: srv.URL, Environment: core.EnvDev}
	_, _ = e.Run(context.Background(), Request{Target: target})
	if !errors.Is(err, ErrOutOfScope) || hits.Load() != 0 {
		t.Fatalf("excluded path not refused: err=%v hits=%d", err, hits.Load())
	}
}

func TestKillSwitchBlocksScans(t *testing.T) {
	srv, _ := testServer(t)
	kill := NewKillSwitch()
	kill.Kill()
	var err error
	e := newEngine(t, Options{Kill: kill}, getCheck("get", srv.URL+"/", &err))
	target := core.Target{Name: "t", URL: srv.URL, Environment: core.EnvDev}
	if _, runErr := e.Run(context.Background(), Request{Target: target}); !errors.Is(runErr, ErrKilled) {
		t.Fatalf("scan started with kill switch engaged: %v", runErr)
	}
	kill.Resume()
	if _, runErr := e.Run(context.Background(), Request{Target: target}); runErr != nil || err != nil {
		t.Fatalf("scan after resume: run=%v req=%v", runErr, err)
	}
}

func TestKillSwitchBlocksRequestsMidScan(t *testing.T) {
	srv, hits := testServer(t)
	kill := NewKillSwitch()
	var err error
	killer := check("a.kill", core.ModePassive, func(context.Context, core.Target) ([]core.Finding, error) {
		kill.Kill()
		return nil, nil
	})
	e := newEngine(t, Options{Kill: kill, Concurrency: 1}, killer, getCheck("b.get", srv.URL+"/", &err))
	target := core.Target{Name: "t", URL: srv.URL, Environment: core.EnvDev}
	_, _ = e.Run(context.Background(), Request{Target: target})
	if !errors.Is(err, ErrKilled) || hits.Load() != 0 {
		t.Fatalf("request after kill not refused: err=%v hits=%d", err, hits.Load())
	}
}

func TestWindow(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 10, 22, h, m, 0, 0, time.UTC) } // a Thursday
	cases := []struct {
		name string
		w    *Window
		t    time.Time
		want bool
	}{
		{"nil allows all", nil, at(12, 0), true},
		{"inside same-day", &Window{Start: "02:00", End: "05:00", Location: time.UTC}, at(3, 30), true},
		{"end is exclusive", &Window{Start: "02:00", End: "05:00", Location: time.UTC}, at(5, 0), false},
		{"outside same-day", &Window{Start: "02:00", End: "05:00", Location: time.UTC}, at(12, 0), false},
		{"wraps late", &Window{Start: "22:00", End: "06:00", Location: time.UTC}, at(23, 0), true},
		{"wraps early", &Window{Start: "22:00", End: "06:00", Location: time.UTC}, at(1, 0), true},
		{"wrap outside", &Window{Start: "22:00", End: "06:00", Location: time.UTC}, at(12, 0), false},
		{"wrong day", &Window{Start: "00:00", End: "23:59", Days: []time.Weekday{time.Monday}, Location: time.UTC}, at(12, 0), false},
		{"right day", &Window{Start: "00:00", End: "23:59", Days: []time.Weekday{time.Thursday}, Location: time.UTC}, at(12, 0), true},
		{"malformed fails closed", &Window{Start: "2am", End: "05:00", Location: time.UTC}, at(3, 0), false},
	}
	for _, c := range cases {
		if got := c.w.Allows(c.t); got != c.want {
			t.Errorf("%s: Allows = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestWindowBlocksScan(t *testing.T) {
	srv, _ := testServer(t)
	noon := func() time.Time { return time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC) }
	w := &Window{Start: "02:00", End: "05:00", Location: time.UTC}
	e := newEngine(t, Options{Window: w, Now: noon})
	target := core.Target{Name: "t", URL: srv.URL, Environment: core.EnvDev}
	if _, err := e.Run(context.Background(), Request{Target: target}); !errors.Is(err, ErrOutsideWindow) {
		t.Fatalf("scan outside window: %v", err)
	}
}

func TestRateLimitSpacesRequests(t *testing.T) {
	srv, hits := testServer(t)
	var errs [6]error
	var checks []core.Check
	for i := range errs {
		checks = append(checks, getCheck(string(rune('a'+i)), srv.URL+"/", &errs[i]))
	}
	// 5 rps with burst 5: six requests need at least ~200ms.
	e := newEngine(t, Options{RateLimit: 5, Concurrency: 6}, checks...)
	target := core.Target{Name: "t", URL: srv.URL, Environment: core.EnvDev}
	start := time.Now()
	_, _ = e.Run(context.Background(), Request{Target: target})
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Fatalf("6 requests at 5 rps took %s; limiter not applied", elapsed)
	}
	if hits.Load() != 6 {
		t.Fatalf("hits = %d, want 6", hits.Load())
	}
}
