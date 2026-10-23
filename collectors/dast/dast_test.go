package dast

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

// withCrawl overrides the discovery seam for one test, pointing the probes at
// a fixed set of URLs, and restores it on cleanup.
func withCrawl(t *testing.T, pages, endpoints []string) {
	t.Helper()
	prev := crawlFn
	crawlFn = func(ctx context.Context, tgt core.Target) (*crawlResult, error) {
		return &crawlResult{Pages: pages, Endpoints: endpoints}, nil
	}
	t.Cleanup(func() { crawlFn = prev })
}

func scanCtx(srv *httptest.Server) context.Context {
	return core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
}

func devTarget(srv *httptest.Server) core.Target {
	return core.Target{URL: srv.URL, Environment: core.EnvDev}
}

// --- skeleton guarantees still hold ------------------------------------

func TestMetadata(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Checks() {
		if c.ID() == "" || seen[c.ID()] {
			t.Fatalf("bad or duplicate ID: %q", c.ID())
		}
		seen[c.ID()] = true
		if c.Category() != core.CategoryApp {
			t.Errorf("%s: category = %v", c.ID(), c.Category())
		}
		if c.Mode() < core.ModePassive || c.Mode() > core.ModeIntrusive {
			t.Errorf("%s: invalid mode", c.ID())
		}
	}
}

func TestRemediationTemplatesPresent(t *testing.T) {
	for _, r := range []core.Remediation{
		RemediationSQLi, RemediationCmdInjection, RemediationSSRF, RemediationPathTraversal, RemediationOpenRedirect, RemediationXSS,
		RemediationSSTI, RemediationXXE, RemediationFileUpload, RemediationBusinessLogic,
	} {
		if r.What == "" || r.Why == "" || len(r.How) == 0 || r.Effort == "" {
			t.Errorf("incomplete remediation template: %+v", r)
		}
	}
}

// Scaffold probes are registered (so they appear in the catalog) but must
// stay no-ops until their logic is written — including against a live target
// with discovered URLs. This guards against a half-wired scaffold shipping.
func TestScaffoldsAreNoops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok " + r.URL.RawQuery))
	}))
	t.Cleanup(srv.Close)
	withCrawl(t, []string{srv.URL + "/?q=1&name=x"}, []string{srv.URL + "/api/ping?host=1"})
	for _, c := range scaffoldChecks() {
		got, err := c.Run(scanCtx(srv), devTarget(srv))
		if err != nil || len(got) != 0 {
			t.Errorf("scaffold %s should be a no-op, got %d findings err=%v", c.ID(), len(got), err)
		}
	}
}

// A URL-less (repo-only) target makes no requests and finds nothing.
func TestRepoOnlyNoFindings(t *testing.T) {
	ctx := core.WithScanCache(context.Background())
	tgt := core.Target{Repo: ".", Environment: core.EnvDev}
	for _, c := range Checks() {
		got, err := c.Run(ctx, tgt)
		if err != nil || len(got) != 0 {
			t.Errorf("%s: repo-only should be a no-op, got %d findings err=%v", c.ID(), len(got), err)
		}
	}
}

// --- open redirect -----------------------------------------------------

func TestOpenRedirect(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if next := r.URL.Query().Get("next"); next != "" {
			w.Header().Set("Location", next) // naive: redirects anywhere
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	withCrawl(t, []string{srv.URL + "/login?next=/home"}, nil)

	got, err := OpenRedirect{}.Run(scanCtx(srv), devTarget(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if got[0].Location != "next" || got[0].Confidence != core.ConfidenceConfirmed {
		t.Errorf("unexpected finding: %+v", got[0])
	}
}

func TestOpenRedirectSafeServer(t *testing.T) {
	// A server that only ever redirects to its own paths is not vulnerable.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("next") != "" {
			w.Header().Set("Location", "/safe") // ignores attacker input
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	withCrawl(t, []string{srv.URL + "/login?next=/home"}, nil)
	got, _ := OpenRedirect{}.Run(scanCtx(srv), devTarget(srv))
	if len(got) != 0 {
		t.Fatalf("want 0 findings for a safe redirect, got %d", len(got))
	}
}

// --- reflected XSS -----------------------------------------------------

func TestReflectedXSS(t *testing.T) {
	t.Run("unescaped reflection", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<p>You searched for: " + r.URL.Query().Get("q") + "</p>"))
		}))
		t.Cleanup(srv.Close)
		withCrawl(t, []string{srv.URL + "/search?q=hello"}, nil)
		got, err := ReflectedXSS{}.Run(scanCtx(srv), devTarget(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Location != "q" {
			t.Fatalf("want 1 finding on q, got %+v", got)
		}
	})
	t.Run("escaped reflection is clean", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			// escape angle brackets, as a safe template would
			q := r.URL.Query().Get("q")
			q = replaceAll(q, "<", "&lt;")
			q = replaceAll(q, ">", "&gt;")
			_, _ = w.Write([]byte("<p>" + q + "</p>"))
		}))
		t.Cleanup(srv.Close)
		withCrawl(t, []string{srv.URL + "/search?q=hello"}, nil)
		got, _ := ReflectedXSS{}.Run(scanCtx(srv), devTarget(srv))
		if len(got) != 0 {
			t.Fatalf("want 0 findings when output is escaped, got %d", len(got))
		}
	})
}

// --- SQL injection -----------------------------------------------------

func TestSQLi(t *testing.T) {
	t.Run("error-based", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.URL.Query().Get("id")
			if containsRune(id, '\'') {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("pq: unterminated quoted string at or near \"'\""))
				return
			}
			_, _ = w.Write([]byte("user 1"))
		}))
		t.Cleanup(srv.Close)
		withCrawl(t, []string{srv.URL + "/u?id=1"}, nil)
		got, err := SQLi{}.Run(scanCtx(srv), devTarget(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Severity != core.SeverityCritical {
			t.Fatalf("want 1 critical, got %+v", got)
		}
	})
	t.Run("parameterized app is clean", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("no such user")) // never errors on a quote
		}))
		t.Cleanup(srv.Close)
		withCrawl(t, []string{srv.URL + "/u?id=1"}, nil)
		got, _ := SQLi{}.Run(scanCtx(srv), devTarget(srv))
		if len(got) != 0 {
			t.Fatalf("want 0, got %d", len(got))
		}
	})
}

// --- path traversal ----------------------------------------------------

func TestPathTraversal(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		if containsStr(f, "etc/passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		_, _ = w.Write([]byte("file not found"))
	}))
	t.Cleanup(srv.Close)
	withCrawl(t, []string{srv.URL + "/download?file=readme.txt"}, nil)
	got, err := PathTraversal{}.Run(scanCtx(srv), devTarget(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Severity != core.SeverityHigh {
		t.Fatalf("want 1 high, got %+v", got)
	}
}

// --- command injection -------------------------------------------------

func TestCommandInjection(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		// Simulate a vulnerable `ping $host` where ; echo MARK runs.
		if i := indexStr(host, "echo "); i >= 0 {
			_, _ = w.Write([]byte("PING output\n" + host[i+len("echo "):] + "\n"))
			return
		}
		_, _ = w.Write([]byte("PING output\n"))
	}))
	t.Cleanup(srv.Close)
	withCrawl(t, []string{srv.URL + "/ping?host=localhost"}, nil)
	got, err := CommandInjection{}.Run(scanCtx(srv), devTarget(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Severity != core.SeverityCritical {
		t.Fatalf("want 1 critical, got %+v", got)
	}
}

// --- SSRF (reflected metadata) -----------------------------------------

func TestSSRF(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("url")
		if containsStr(u, "169.254.169.254") {
			// Simulate the server fetching metadata and reflecting it.
			_, _ = w.Write([]byte("ami-id\niam\nmeta-data\n"))
			return
		}
		_, _ = w.Write([]byte("fetched"))
	}))
	t.Cleanup(srv.Close)
	withCrawl(t, []string{srv.URL + "/fetch?url=http://example.com"}, nil)
	got, err := SSRF{}.Run(scanCtx(srv), devTarget(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Severity != core.SeverityHigh {
		t.Fatalf("want 1 high, got %+v", got)
	}
}

// --- tiny local string helpers (keep test deps minimal) ----------------

func replaceAll(s, old, new string) string {
	out := ""
	for {
		i := indexStr(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}

func indexStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func containsStr(s, sub string) bool { return indexStr(s, sub) >= 0 }

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
