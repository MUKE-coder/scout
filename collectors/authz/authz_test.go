package authz

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MUKE-coder/scout/collectors/crawl"
	"github.com/MUKE-coder/scout/core"
)

func withCrawl(t *testing.T, pages, endpoints []string, forms []crawl.Form) {
	t.Helper()
	prev := crawlFn
	crawlFn = func(ctx context.Context, tgt core.Target) (*crawlResult, error) {
		return &crawlResult{Pages: pages, Endpoints: endpoints, Forms: forms}, nil
	}
	t.Cleanup(func() { crawlFn = prev })
}

func scanCtx(srv *httptest.Server) context.Context {
	return core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
}

func devTarget(srv *httptest.Server) core.Target {
	return core.Target{URL: srv.URL, Environment: core.EnvDev}
}

func TestMetadata(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Checks() {
		if c.ID() == "" || seen[c.ID()] {
			t.Fatalf("bad or duplicate ID: %q", c.ID())
		}
		seen[c.ID()] = true
		if c.Category() != core.CategoryAuth {
			t.Errorf("%s: category = %v", c.ID(), c.Category())
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

// Unimplemented checks must stay safe no-ops.
func TestUnimplementedAreNoops(t *testing.T) {
	ctx := core.WithScanCache(context.Background())
	tgt := core.Target{URL: "http://localhost:8080", Environment: core.EnvDev}
	for _, c := range []core.Check{IDOR{}, MassAssignment{}} {
		got, err := c.Run(ctx, tgt)
		if err != nil || len(got) != 0 {
			t.Errorf("%s: want no-op, got %d findings err=%v", c.ID(), len(got), err)
		}
	}
}

// Only implemented checks are registered.
func TestOnlyImplementedRegistered(t *testing.T) {
	want := map[string]bool{"auth.jwt": true, "auth.missing": true, "auth.cors": true}
	for _, c := range implementedChecks() {
		if !want[c.ID()] {
			t.Errorf("unexpected registered check %q", c.ID())
		}
		delete(want, c.ID())
	}
	if len(want) != 0 {
		t.Errorf("missing implemented checks: %v", want)
	}
}

// --- CORS --------------------------------------------------------------

func TestCORS(t *testing.T) {
	t.Run("reflects origin with credentials", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if o := r.Header.Get("Origin"); o != "" {
				w.Header().Set("Access-Control-Allow-Origin", o) // reflects anything
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)
		withCrawl(t, []string{srv.URL}, nil, nil)
		got, err := CORS{}.Run(scanCtx(srv), devTarget(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Severity != core.SeverityHigh {
			t.Fatalf("want 1 high, got %+v", got)
		}
	})
	t.Run("strict cors is clean", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)
		withCrawl(t, []string{srv.URL}, nil, nil)
		got, _ := CORS{}.Run(scanCtx(srv), devTarget(srv))
		if len(got) != 0 {
			t.Fatalf("want 0, got %d", len(got))
		}
	})
}

// --- JWT ---------------------------------------------------------------

func makeJWT(t *testing.T, headerJSON, claimsJSON string) string {
	t.Helper()
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(headerJSON) + "." + enc(claimsJSON) + "." + enc("sig")
}

func TestJWT(t *testing.T) {
	t.Run("alg none in cookie", func(t *testing.T) {
		tok := makeJWT(t, `{"alg":"none","typ":"JWT"}`, `{"sub":"1"}`)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: tok})
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)
		withCrawl(t, []string{srv.URL}, nil, nil)
		got, err := JWT{}.Run(scanCtx(srv), devTarget(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Severity != core.SeverityHigh {
			t.Fatalf("want 1 high (alg:none), got %+v", got)
		}
		if !got[0].Evidence.Redacted {
			t.Error("jwt evidence should be redacted")
		}
	})
	t.Run("signed with expiry is clean", func(t *testing.T) {
		tok := makeJWT(t, `{"alg":"HS256","typ":"JWT"}`, `{"sub":"1","exp":9999999999}`)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: tok})
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)
		withCrawl(t, []string{srv.URL}, nil, nil)
		got, _ := JWT{}.Run(scanCtx(srv), devTarget(srv))
		if len(got) != 0 {
			t.Fatalf("want 0 for a healthy token, got %+v", got)
		}
	})
}

// --- MissingAuth -------------------------------------------------------

func TestMissingAuthRouteTable(t *testing.T) {
	// No HTTP needed: the route table alone proves the gap.
	ctx := core.WithScanCache(context.Background())
	tgt := core.Target{
		URL:         "https://app.example.com",
		Environment: core.EnvProd,
		Routes: []core.Route{
			{Method: "GET", Path: "/admin/users", Middleware: []string{"Logger"}},            // no auth → finding
			{Method: "GET", Path: "/admin/stats", Middleware: []string{"Logger", "JWTAuth"}}, // protected → clean
			{Method: "GET", Path: "/", Middleware: []string{"Logger"}},                       // not sensitive → clean
		},
	}
	// Discovery returns nothing (route-table-only path).
	prev := crawlFn
	crawlFn = func(context.Context, core.Target) (*crawlResult, error) { return &crawlResult{}, nil }
	t.Cleanup(func() { crawlFn = prev })

	got, err := MissingAuth{}.Run(ctx, tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Location != "GET /admin/users" || got[0].Confidence != core.ConfidenceConfirmed {
		t.Errorf("unexpected finding: %+v", got[0])
	}
}

func TestMissingAuthHTTP(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /api/account returns data with no auth check.
		_, _ = w.Write([]byte(`{"balance": 100}`))
	}))
	t.Cleanup(srv.Close)
	withCrawl(t, []string{srv.URL}, []string{srv.URL + "/api/account"}, nil)
	got, err := MissingAuth{}.Run(scanCtx(srv), devTarget(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Confidence != core.ConfidenceLikely {
		t.Fatalf("want 1 likely finding, got %+v", got)
	}
}
