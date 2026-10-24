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

// MassAssignment stays a safe no-op; IDOR is a no-op only until identities are
// configured (exercised in TestIDOR).
func TestUnimplementedAreNoops(t *testing.T) {
	ctx := core.WithScanCache(context.Background())
	tgt := core.Target{URL: "http://localhost:8080", Environment: core.EnvDev}
	for _, c := range []core.Check{MassAssignment{}} {
		got, err := c.Run(ctx, tgt)
		if err != nil || len(got) != 0 {
			t.Errorf("%s: want no-op, got %d findings err=%v", c.ID(), len(got), err)
		}
	}
	// IDOR with no identities configured must also report nothing.
	if got, err := (IDOR{}).Run(ctx, tgt); err != nil || len(got) != 0 {
		t.Errorf("IDOR unconfigured: want no-op, got %d findings err=%v", len(got), err)
	}
}

// Only implemented checks are registered.
func TestOnlyImplementedRegistered(t *testing.T) {
	want := map[string]bool{"auth.jwt": true, "auth.missing": true, "auth.cors": true, "auth.idor": true}
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

// --- IDOR --------------------------------------------------------------

func TestIDOR(t *testing.T) {
	// Two owned objects; alice owns /1, bob owns /2. A server ignoring the
	// caller's identity (returning the object for any authenticated request)
	// is vulnerable; one that checks ownership is not.
	objects := map[string]string{
		"/api/users/1": `{"id":1,"email":"alice@example.com","ssn":"111"}`,
		"/api/users/2": `{"id":2,"email":"bob@example.com","ssn":"222"}`,
	}
	identities := []core.Identity{
		{Name: "alice", Headers: map[string]string{"X-Test-User": "alice"}, Owns: []string{"/api/users/1"}},
		{Name: "bob", Headers: map[string]string{"X-Test-User": "bob"}, Owns: []string{"/api/users/2"}},
	}

	t.Run("no ownership check is flagged", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if body, ok := objects[r.URL.Path]; ok {
				_, _ = w.Write([]byte(body)) // serves the object to anyone
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(srv.Close)
		tgt := devTarget(srv)
		tgt.Identities = identities
		got, err := IDOR{}.Run(scanCtx(srv), tgt)
		if err != nil {
			t.Fatal(err)
		}
		// bob can read alice's object and vice versa → 2 findings.
		if len(got) != 2 {
			t.Fatalf("want 2 IDOR findings, got %d: %+v", len(got), got)
		}
		for _, f := range got {
			if f.Severity != core.SeverityHigh || f.Confidence != core.ConfidenceConfirmed {
				t.Errorf("idor finding not high/confirmed: %+v", f)
			}
			if !f.Evidence.Redacted {
				t.Error("idor evidence must be redacted (no private body stored)")
			}
			if f.CWE[0] != "CWE-639" {
				t.Errorf("cwe = %v", f.CWE)
			}
		}
	})

	t.Run("enforced ownership is clean", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := r.Header.Get("X-Test-User")
			owner := map[string]string{"/api/users/1": "alice", "/api/users/2": "bob"}[r.URL.Path]
			if owner == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if user != owner {
				w.WriteHeader(http.StatusForbidden) // ownership enforced
				return
			}
			_, _ = w.Write([]byte(objects[r.URL.Path]))
		}))
		t.Cleanup(srv.Close)
		tgt := devTarget(srv)
		tgt.Identities = identities
		got, err := IDOR{}.Run(scanCtx(srv), tgt)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("want 0 findings for an app that enforces ownership, got %+v", got)
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

// From GitHub issue #2: a namespaced API must not make every route "sensitive",
// sign-in/health routes are public by design, and the Public flag is honoured.
func TestMissingAuthPublicRoutes(t *testing.T) {
	ctx := core.WithScanCache(context.Background())
	tgt := core.Target{
		URL:         "https://app.example.com",
		Environment: core.EnvProd,
		Routes: []core.Route{
			{Method: "POST", Path: "/api/v1/auth/login", Middleware: nil},                // sign-in → public
			{Method: "GET", Path: "/api/health", Middleware: nil},                        // health → public
			{Method: "GET", Path: "/api/v1/auth/oauth/google/callback", Middleware: nil}, // OAuth callback → public
			{Method: "GET", Path: "/api/v1/users", Middleware: nil, Public: true},        // declared public
			{Method: "GET", Path: "/api/v1/admin/users", Middleware: nil},                // genuinely unprotected → finding
		},
	}
	prev := crawlFn
	crawlFn = func(context.Context, core.Target) (*crawlResult, error) { return &crawlResult{}, nil }
	t.Cleanup(func() { crawlFn = prev })

	got, err := MissingAuth{}.Run(ctx, tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Location != "GET /api/v1/admin/users" {
		t.Fatalf("want only the admin route flagged, got %d: %+v", len(got), got)
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
