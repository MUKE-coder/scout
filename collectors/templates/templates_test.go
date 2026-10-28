package templates

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

func pageFor(body string, status int, response string) *httpx.Page {
	return &httpx.Page{Status: status, Body: []byte(body), Response: response}
}

func scanCtx(srv *httptest.Server) context.Context {
	return core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
}

func TestSafeGate(t *testing.T) {
	cases := []struct {
		r    Request
		safe bool
	}{
		{Request{Method: "GET", Path: []string{"/x"}}, true},
		{Request{Path: []string{"/x"}}, true}, // default GET
		{Request{Method: "POST", Path: []string{"/x"}}, false},
		{Request{Method: "GET", Path: []string{"/x"}, Body: "payload"}, false},
		{Request{Method: "GET", Raw: []string{"GET / HTTP/1.1"}}, false},
		{Request{Method: "GET"}, false}, // no path
	}
	for i, c := range cases {
		if c.r.safe() != c.safe {
			t.Errorf("case %d: safe()=%v, want %v", i, c.r.safe(), c.safe)
		}
	}
}

func TestBuiltinTemplatesLoad(t *testing.T) {
	if len(loadBuiltin()) < 3 {
		t.Fatalf("expected at least 3 built-in templates, got %d", len(loadBuiltin()))
	}
}

func TestRunMatchesApacheStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/server-status" {
			_, _ = w.Write([]byte("<h1>Apache Server Status for example</h1><table>Scoreboard: ___</table>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got, err := Check{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range got {
		if f.Location == "apache-server-status" {
			found = true
			if f.Severity != core.SeverityMedium {
				t.Errorf("severity = %v", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("apache-server-status template should match: %+v", got)
	}
}

func TestRunNoMatchOnCleanApp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	got, _ := Check{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if len(got) != 0 {
		t.Fatalf("clean app should produce no template findings, got %+v", got)
	}
}

func TestMatchers(t *testing.T) {
	page := pageFor("body has SECRET token", 200, "Server: nginx")
	// word AND present
	if !matches(Request{Matchers: []Matcher{{Type: "word", Words: flexStrings{"secret", "token"}, Condition: "and"}}}, page) {
		t.Error("word AND should match")
	}
	// status
	if !matches(Request{Matchers: []Matcher{{Type: "status", Status: []int{200}}}}, page) {
		t.Error("status should match")
	}
	// negative word
	if !matches(Request{Matchers: []Matcher{{Type: "word", Words: flexStrings{"absent"}, Negative: true}}}, page) {
		t.Error("negative word should match when word absent")
	}
	// AND of status + missing word fails
	if matches(Request{MatchersCond: "and", Matchers: []Matcher{{Type: "status", Status: []int{200}}, {Type: "word", Words: flexStrings{"absent"}}}}, page) {
		t.Error("AND with a missing word must not match")
	}
}
