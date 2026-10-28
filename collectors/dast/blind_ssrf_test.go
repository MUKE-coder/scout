package dast

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
)

// TestBlindSSRF stands up a target that fetches whatever URL is passed in its
// `url` parameter (classic SSRF), then confirms the blind-SSRF check sees the
// out-of-band callback to Scout's own OAST listener.
func TestBlindSSRF(t *testing.T) {
	prev := oobGrace
	oobGrace = 500 * time.Millisecond
	t.Cleanup(func() { oobGrace = prev })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cb := r.URL.Query().Get("url"); strings.HasPrefix(cb, "http://127.0.0.1") {
			// Simulate SSRF: the server fetches the attacker-supplied URL.
			resp, err := http.Get(cb) // #nosec G107 -- deliberate SSRF simulation to a local listener
			if err == nil {
				_ = resp.Body.Close()
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	withCrawl(t, []string{srv.URL + "/fetch?url=http://example.com"}, nil)
	got, err := BlindSSRF{}.Run(scanCtx(srv), devTarget(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Location != "url" {
		t.Fatalf("want 1 blind-SSRF finding on param url, got %+v", got)
	}
	if got[0].Confidence != core.ConfidenceConfirmed {
		t.Errorf("blind SSRF should be confirmed (OAST callback observed): %+v", got[0])
	}
}

// A target that does NOT fetch the parameter must produce no finding.
func TestBlindSSRFSafeServer(t *testing.T) {
	prev := oobGrace
	oobGrace = 500 * time.Millisecond
	t.Cleanup(func() { oobGrace = prev })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok")) // never fetches the param
	}))
	defer srv.Close()

	withCrawl(t, []string{srv.URL + "/fetch?url=http://example.com"}, nil)
	got, _ := BlindSSRF{}.Run(scanCtx(srv), devTarget(srv))
	if len(got) != 0 {
		t.Fatalf("safe server must produce no blind-SSRF finding, got %+v", got)
	}
}
