package engine

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
)

// fakeResolver serves TXT records from a map.
type fakeResolver map[string][]string

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if r, ok := f[name]; ok {
		return r, nil
	}
	return nil, errors.New("no such host")
}

// stubTransport answers every request in-process: it serves body for the
// well-known path and 404 for anything else. No network is touched.
type stubTransport struct {
	wellKnown string
	hits      atomic.Int32
}

func (s *stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.hits.Add(1)
	status, body := http.StatusNotFound, ""
	if r.URL.Path == WellKnownPath && s.wellKnown != "" {
		status, body = http.StatusOK, s.wellKnown
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
}

var remote = core.Target{Name: "site", URL: "https://shop.example.com/app", Environment: core.EnvProd, AllowActive: true}

func activeEngine(t *testing.T, key []byte, res Resolver, tr http.RoundTripper) (*Engine, *atomic.Int32) {
	t.Helper()
	var activeRuns atomic.Int32
	v := NewVerifier(key)
	v.Resolver = res
	e := newEngine(t, Options{SigningKey: key, Verifier: v, Transport: tr},
		check("x.active", core.ModeActive, func(context.Context, core.Target) ([]core.Finding, error) {
			activeRuns.Add(1)
			return nil, nil
		}),
	)
	return e, &activeRuns
}

func TestOwnershipToken(t *testing.T) {
	a := OwnershipToken([]byte("k1"), "Shop.Example.com.")
	if a != OwnershipToken([]byte("k1"), "shop.example.com") {
		t.Fatal("token must ignore case and trailing dot")
	}
	if a == OwnershipToken([]byte("k2"), "shop.example.com") || a == OwnershipToken([]byte("k1"), "other.com") {
		t.Fatal("token must depend on key and host")
	}
	if len(OwnershipToken(nil, "x.com")) != 32 {
		t.Fatal("unkeyed token should still be 32 hex chars")
	}
}

func TestUnverifiedRemoteDropsToSafe(t *testing.T) {
	e, activeRuns := activeEngine(t, []byte("key"), fakeResolver{}, &stubTransport{})
	res, err := e.Run(context.Background(), Request{Target: remote, Mode: core.ModeActive})
	if err != nil {
		t.Fatal(err)
	}
	if activeRuns.Load() != 0 || res.Mode != core.ModeSafe {
		t.Fatalf("active check ran without ownership proof (mode %v)", res.Mode)
	}
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "ownership not verified") ||
		!strings.Contains(res.Skipped[0].Reason, TXTPrefix) {
		t.Fatalf("skip reason should explain how to verify: %+v", res.Skipped)
	}
}

func TestVerifiedByDNS(t *testing.T) {
	key := []byte("key")
	token := OwnershipToken(key, "shop.example.com")
	for _, name := range []string{"_scout-verify.shop.example.com", "shop.example.com"} {
		e, activeRuns := activeEngine(t, key, fakeResolver{name: {"v=spf1 -all", TXTPrefix + token}}, &stubTransport{})
		res, _ := e.Run(context.Background(), Request{Target: remote, Mode: core.ModeActive})
		if activeRuns.Load() != 1 || res.Mode != core.ModeActive {
			t.Fatalf("TXT on %s not accepted (mode %v, skipped %+v)", name, res.Mode, res.Skipped)
		}
	}
}

func TestVerifiedByWellKnown(t *testing.T) {
	key := []byte("key")
	tr := &stubTransport{wellKnown: "# scout\n" + OwnershipToken(key, "shop.example.com") + "\n"}
	e, activeRuns := activeEngine(t, key, fakeResolver{}, tr)
	if _, err := e.Run(context.Background(), Request{Target: remote, Mode: core.ModeActive}); err != nil {
		t.Fatal(err)
	}
	if activeRuns.Load() != 1 {
		t.Fatal("well-known token not accepted")
	}
}

func TestWrongTokenRejected(t *testing.T) {
	key := []byte("key")
	tr := &stubTransport{wellKnown: OwnershipToken([]byte("someone-else"), "shop.example.com")}
	e, activeRuns := activeEngine(t, key, fakeResolver{"shop.example.com": {TXTPrefix + "deadbeef"}}, tr)
	_, _ = e.Run(context.Background(), Request{Target: remote, Mode: core.ModeActive})
	if activeRuns.Load() != 0 {
		t.Fatal("wrong token accepted")
	}
}

func TestLocalAndSafeSkipVerification(t *testing.T) {
	tr := &stubTransport{}
	e, activeRuns := activeEngine(t, []byte("key"), fakeResolver{}, tr)
	local := core.Target{Name: "l", URL: "http://localhost:8080", Environment: core.EnvDev}
	if _, err := e.Run(context.Background(), Request{Target: local, Mode: core.ModeActive}); err != nil {
		t.Fatal(err)
	}
	if activeRuns.Load() != 1 {
		t.Fatal("local target should not need ownership proof")
	}
	// A safe scan of a remote host never looks up ownership.
	if _, err := e.Run(context.Background(), Request{Target: remote, Mode: core.ModeSafe}); err != nil {
		t.Fatal(err)
	}
	if tr.hits.Load() != 0 {
		t.Fatalf("ownership lookup sent %d requests for a scan that did not need it", tr.hits.Load())
	}
}

func TestVerificationCached(t *testing.T) {
	key := []byte("key")
	tr := &stubTransport{wellKnown: OwnershipToken(key, "shop.example.com")}
	v := NewVerifier(key)
	v.Resolver = fakeResolver{}
	clock := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	v.Now = func() time.Time { return clock }
	client := &http.Client{Transport: tr}

	for i, want := range []string{"well-known", "cached"} {
		got, err := v.Verify(context.Background(), remote, client)
		if err != nil || got != want {
			t.Fatalf("call %d: method = %q, err = %v; want %q", i, got, err, want)
		}
	}
	clock = clock.Add(2 * time.Hour) // past TTL
	if got, _ := v.Verify(context.Background(), remote, client); got != "well-known" {
		t.Fatalf("after TTL method = %q, want fresh check", got)
	}
}

func TestPlanReflectsOwnership(t *testing.T) {
	e, activeRuns := activeEngine(t, []byte("key"), fakeResolver{}, &stubTransport{})
	p, err := e.Plan(context.Background(), Request{Target: remote, Mode: core.ModeActive})
	if err != nil {
		t.Fatal(err)
	}
	if p.Effective != core.ModeSafe || activeRuns.Load() != 0 || !strings.Contains(p.CapReason, "ownership not verified") {
		t.Fatalf("plan = %+v", p)
	}
}
