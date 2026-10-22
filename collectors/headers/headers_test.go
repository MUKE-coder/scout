package headers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

// scanCtx wires a test server's client into the guarded-client + scan-cache
// context, the way the engine does for a real scan.
func scanCtx(srv *httptest.Server) context.Context {
	return core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
}

func target(srv *httptest.Server) core.Target {
	return core.Target{URL: srv.URL, Environment: core.EnvDev}
}

// serveHeaders starts a TLS test server whose root response carries the given
// headers (and optional Set-Cookie lines via setCookies).
func serveHeaders(t *testing.T, hdr map[string]string, setCookies ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		for _, c := range setCookies {
			w.Header().Add("Set-Cookie", c)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runCheck(t *testing.T, c core.Check, srv *httptest.Server) []core.Finding {
	t.Helper()
	got, err := c.Run(scanCtx(srv), target(srv))
	if err != nil {
		t.Fatalf("%s.Run: %v", c.ID(), err)
	}
	return got
}

// --- NoSniff ---

func TestNoSniff(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		srv := serveHeaders(t, nil)
		got := runCheck(t, NoSniff{}, srv)
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if got[0].Severity != core.SeverityLow {
			t.Errorf("severity = %s, want low", got[0].Severity)
		}
		if got[0].Asset.Kind != core.AssetURL {
			t.Errorf("asset kind = %s, want url", got[0].Asset.Kind)
		}
		if len(got[0].Remediation.How) == 0 {
			t.Error("remediation has no fixes")
		}
	})
	t.Run("present", func(t *testing.T) {
		srv := serveHeaders(t, map[string]string{"X-Content-Type-Options": "nosniff"})
		if got := runCheck(t, NoSniff{}, srv); len(got) != 0 {
			t.Fatalf("want 0 findings, got %d", len(got))
		}
	})
}

// --- HSTS ---

func TestHSTS(t *testing.T) {
	t.Run("missing on https", func(t *testing.T) {
		srv := serveHeaders(t, nil)
		got := runCheck(t, HSTS{}, srv)
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if got[0].Severity != core.SeverityMedium {
			t.Errorf("severity = %s, want medium", got[0].Severity)
		}
	})
	t.Run("present", func(t *testing.T) {
		srv := serveHeaders(t, map[string]string{"Strict-Transport-Security": "max-age=63072000"})
		if got := runCheck(t, HSTS{}, srv); len(got) != 0 {
			t.Fatalf("want 0 findings, got %d", len(got))
		}
	})
}

// --- Clickjacking ---

func TestClickjacking(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		srv := serveHeaders(t, nil)
		if got := runCheck(t, Clickjacking{}, srv); len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
	})
	t.Run("x-frame-options present", func(t *testing.T) {
		srv := serveHeaders(t, map[string]string{"X-Frame-Options": "DENY"})
		if got := runCheck(t, Clickjacking{}, srv); len(got) != 0 {
			t.Fatalf("want 0 findings, got %d", len(got))
		}
	})
	t.Run("frame-ancestors in csp satisfies it", func(t *testing.T) {
		srv := serveHeaders(t, map[string]string{"Content-Security-Policy": "frame-ancestors 'none'"})
		if got := runCheck(t, Clickjacking{}, srv); len(got) != 0 {
			t.Fatalf("want 0 findings, got %d", len(got))
		}
	})
}

// --- CSP ---

func TestCSP(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		srv := serveHeaders(t, nil)
		if got := runCheck(t, CSP{}, srv); len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
	})
	t.Run("present", func(t *testing.T) {
		srv := serveHeaders(t, map[string]string{"Content-Security-Policy": "default-src 'self'"})
		if got := runCheck(t, CSP{}, srv); len(got) != 0 {
			t.Fatalf("want 0 findings, got %d", len(got))
		}
	})
}

// --- ReferrerPolicy ---

func TestReferrerPolicy(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		srv := serveHeaders(t, nil)
		if got := runCheck(t, ReferrerPolicy{}, srv); len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
	})
	t.Run("present", func(t *testing.T) {
		srv := serveHeaders(t, map[string]string{"Referrer-Policy": "no-referrer"})
		if got := runCheck(t, ReferrerPolicy{}, srv); len(got) != 0 {
			t.Fatalf("want 0 findings, got %d", len(got))
		}
	})
}

// --- PermissionsPolicy ---

func TestPermissionsPolicy(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		srv := serveHeaders(t, nil)
		if got := runCheck(t, PermissionsPolicy{}, srv); len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
	})
	t.Run("present", func(t *testing.T) {
		srv := serveHeaders(t, map[string]string{"Permissions-Policy": "geolocation=()"})
		if got := runCheck(t, PermissionsPolicy{}, srv); len(got) != 0 {
			t.Fatalf("want 0 findings, got %d", len(got))
		}
	})
}

// --- ServerDisclosure ---

func TestServerDisclosure(t *testing.T) {
	t.Run("versioned server header", func(t *testing.T) {
		srv := serveHeaders(t, map[string]string{"Server": "nginx/1.25.3"})
		got := runCheck(t, ServerDisclosure{}, srv)
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if got[0].Location != "Server" {
			t.Errorf("location = %q, want Server", got[0].Location)
		}
		if got[0].Severity != core.SeverityInfo {
			t.Errorf("severity = %s, want info", got[0].Severity)
		}
	})
	t.Run("both headers versioned", func(t *testing.T) {
		srv := serveHeaders(t, map[string]string{"Server": "Apache/2.4.58", "X-Powered-By": "PHP/8.2.1"})
		got := runCheck(t, ServerDisclosure{}, srv)
		if len(got) != 2 {
			t.Fatalf("want 2 findings, got %d", len(got))
		}
		// Deterministic order: Server before X-Powered-By.
		if got[0].Location != "Server" || got[1].Location != "X-Powered-By" {
			t.Errorf("order = %q,%q; want Server,X-Powered-By", got[0].Location, got[1].Location)
		}
	})
	t.Run("no version is not flagged", func(t *testing.T) {
		srv := serveHeaders(t, map[string]string{"Server": "cloudflare"})
		if got := runCheck(t, ServerDisclosure{}, srv); len(got) != 0 {
			t.Fatalf("want 0 findings, got %d", len(got))
		}
	})
}

// --- CookieFlags ---

func TestCookieFlags(t *testing.T) {
	t.Run("insecure session cookie", func(t *testing.T) {
		srv := serveHeaders(t, nil, "session_id=abc123; Path=/")
		got := runCheck(t, CookieFlags{}, srv)
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		f := got[0]
		if f.Location != "session_id" {
			t.Errorf("location = %q, want session_id", f.Location)
		}
		if f.Severity != core.SeverityMedium {
			t.Errorf("severity = %s, want medium (session cookie)", f.Severity)
		}
		if contains(splitMatched(f.Evidence.Matched), "abc123") {
			t.Error("cookie value leaked into evidence; should be redacted")
		}
	})
	t.Run("hardened cookie passes", func(t *testing.T) {
		srv := serveHeaders(t, nil, "session_id=abc123; Path=/; HttpOnly; Secure; SameSite=Lax")
		if got := runCheck(t, CookieFlags{}, srv); len(got) != 0 {
			t.Fatalf("want 0 findings, got %d", len(got))
		}
	})
	t.Run("two weak cookies sorted by name", func(t *testing.T) {
		srv := serveHeaders(t, nil, "btoken=2; Path=/", "atoken=1; Path=/")
		got := runCheck(t, CookieFlags{}, srv)
		if len(got) != 2 {
			t.Fatalf("want 2 findings, got %d", len(got))
		}
		if got[0].Location != "atoken" || got[1].Location != "btoken" {
			t.Errorf("order = %q,%q; want atoken,btoken", got[0].Location, got[1].Location)
		}
	})
}

// splitMatched is a tiny helper so the redaction assertion reads clearly.
func splitMatched(s string) []string { return []string{s} }

// repo-only target: every check returns nothing, no request made.
func TestRepoOnlyTargetNoFindings(t *testing.T) {
	ctx := core.WithScanCache(context.Background()) // no HTTP client attached
	tgt := core.Target{Repo: ".", Environment: core.EnvDev}
	for _, c := range []core.Check{
		NoSniff{}, HSTS{}, Clickjacking{}, CSP{}, ReferrerPolicy{},
		PermissionsPolicy{}, ServerDisclosure{}, CookieFlags{},
	} {
		got, err := c.Run(ctx, tgt)
		if err != nil {
			t.Errorf("%s: unexpected error on repo-only target: %v", c.ID(), err)
		}
		if len(got) != 0 {
			t.Errorf("%s: want 0 findings on repo-only target, got %d", c.ID(), len(got))
		}
	}
}
