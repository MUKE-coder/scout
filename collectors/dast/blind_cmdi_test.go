package dast

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
)

// cbURL pulls the first http://127.0.0.1/... callback out of an injected value.
var cbURL = regexp.MustCompile(`http://127\.0\.0\.1:\d+/[A-Za-z0-9]+`)

// TestBlindCommandInjection simulates a server that passes the `host` parameter
// to a shell: if the value contains our curl callback, the "shell" fetches it.
func TestBlindCommandInjection(t *testing.T) {
	prev := oobGrace
	oobGrace = 500 * time.Millisecond
	t.Cleanup(func() { oobGrace = prev })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("host")
		// Pretend the value is interpolated into a shell command; the benign curl
		// in it "executes" and reaches our listener.
		if u := cbURL.FindString(v); u != "" {
			resp, err := http.Get(u) // #nosec G107 -- simulates the injected command's outbound request
			if err == nil {
				_ = resp.Body.Close()
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	withCrawl(t, []string{srv.URL + "/ping?host=1"}, nil)
	got, err := BlindCommandInjection{}.Run(scanCtx(srv), devTarget(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Location != "host" {
		t.Fatalf("want 1 blind-cmdi finding on param host, got %+v", got)
	}
	if got[0].Severity != core.SeverityCritical || got[0].Confidence != core.ConfidenceConfirmed {
		t.Errorf("blind cmdi should be critical/confirmed: %+v", got[0])
	}
}

func TestBlindCommandInjectionSafeServer(t *testing.T) {
	prev := oobGrace
	oobGrace = 500 * time.Millisecond
	t.Cleanup(func() { oobGrace = prev })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok")) // never executes the value
	}))
	defer srv.Close()

	withCrawl(t, []string{srv.URL + "/ping?host=1"}, nil)
	got, _ := BlindCommandInjection{}.Run(scanCtx(srv), devTarget(srv))
	if len(got) != 0 {
		t.Fatalf("safe server must produce no blind-cmdi finding, got %+v", got)
	}
}
