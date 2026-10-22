package crawl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

// site serves a tiny app: a home page linking to two pages and an API, one
// page with a CSRF-protected POST form, one with an unprotected POST form,
// and one with a GET search form (not state-changing).
func site(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	html := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><body>" + body + "</body></html>"))
		}
	}
	mux.HandleFunc("/", html(`<a href="/safe">safe</a> <a href="/unsafe">unsafe</a> <a href="/search">search</a> <a href="/api/todos">api</a> <a href="https://evil.example.com/x">offsite</a>`))
	mux.HandleFunc("/safe", html(`<form method="post" action="/safe"><input name="csrf_token" type="hidden"><input name="title"></form>`))
	mux.HandleFunc("/unsafe", html(`<form method="POST" action="/unsafe/do"><input name="amount"><input name="to"></form>`))
	mux.HandleFunc("/search", html(`<form method="get" action="/search"><input name="q"></form>`))
	mux.HandleFunc("/api/todos", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func scanCtx(srv *httptest.Server) context.Context {
	return core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
}

func TestCrawlDiscoversPagesFormsEndpoints(t *testing.T) {
	srv := site(t)
	res, err := Crawl(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pages) < 4 {
		t.Fatalf("pages = %v", res.Pages)
	}
	if len(res.Forms) != 3 {
		t.Fatalf("forms = %d, want 3", len(res.Forms))
	}
	var sawEndpoint bool
	for _, e := range res.Endpoints {
		if contains(e, "/api/todos") {
			sawEndpoint = true
		}
		if contains(e, "evil.example.com") {
			t.Fatalf("crawler left the target host: %s", e)
		}
	}
	if !sawEndpoint {
		t.Fatalf("api endpoint not discovered: %v", res.Endpoints)
	}
}

func TestCSRFFinding(t *testing.T) {
	srv := site(t)
	got, err := Forms{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	// Only the /unsafe POST form (no token) should be flagged — not the
	// token-protected POST, nor the GET search form.
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.Severity != core.SeverityMedium || f.CWE[0] != "CWE-352" {
		t.Fatalf("finding = %+v", f)
	}
	if !contains(f.Location, "/unsafe/do") {
		t.Fatalf("wrong form flagged: %s", f.Location)
	}
}

func TestNoURLNoCrawl(t *testing.T) {
	got, err := Forms{}.Run(core.WithScanCache(context.Background()), core.Target{Repo: ".", Environment: core.EnvDev})
	if err != nil || got != nil {
		t.Fatalf("repo-only target: %v %v", got, err)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
