package clientside

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func scanCtx(srv *httptest.Server) context.Context {
	return core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
}

func serve(t *testing.T, tls bool, body string) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body))
	})
	if tls {
		return httptest.NewTLSServer(h)
	}
	return httptest.NewServer(h)
}

func TestMissingSRI(t *testing.T) {
	const page = `<html><head>
<script src="https://cdn.evil-looking.example/lib.js"></script>
<script src="https://cdn.example.com/ok.js" integrity="sha384-abc"></script>
<script src="/local/app.js"></script>
<link rel="stylesheet" href="https://cdn.example.com/style.css">
<link rel="icon" href="https://cdn.example.com/favicon.ico">
</head><body>hi</body></html>`

	srv := serve(t, false, page)
	defer srv.Close()
	got, err := MissingSRI{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	// Flagged: the external lib.js (no integrity) and the external stylesheet.
	// Not flagged: ok.js (has integrity), app.js (same-origin), favicon (icon,
	// not a stylesheet).
	if len(got) != 2 {
		t.Fatalf("want 2 SRI findings, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.Severity != core.SeverityMedium || f.CWE[0] != "CWE-353" {
			t.Errorf("unexpected SRI finding: %+v", f)
		}
	}
}

func TestMissingSRISameOriginClean(t *testing.T) {
	const page = `<html><head><script src="app.js"></script></head></html>`
	srv := serve(t, false, page)
	defer srv.Close()
	got, _ := MissingSRI{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if len(got) != 0 {
		t.Fatalf("same-origin script should not need SRI: %+v", got)
	}
}

func TestMixedContentOnHTTPS(t *testing.T) {
	const page = `<html><head>
<script src="http://cdn.example.com/lib.js"></script>
<img src="http://cdn.example.com/pic.png">
<link rel="stylesheet" href="https://cdn.example.com/s.css">
</head></html>`
	srv := serve(t, true, page) // HTTPS server
	defer srv.Close()
	got, err := MixedContent{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	// http script (active, High) + http img (passive, Low); https stylesheet clean.
	if len(got) != 2 {
		t.Fatalf("want 2 mixed-content findings, got %d: %+v", len(got), got)
	}
	var high, low int
	for _, f := range got {
		switch f.Severity {
		case core.SeverityHigh:
			high++
		case core.SeverityLow:
			low++
		}
		if f.CWE[0] != "CWE-311" {
			t.Errorf("cwe = %v", f.CWE)
		}
	}
	if high != 1 || low != 1 {
		t.Fatalf("want 1 high (script) + 1 low (img), got high=%d low=%d", high, low)
	}
}

func TestMixedContentIgnoredOnHTTP(t *testing.T) {
	const page = `<html><head><script src="http://cdn.example.com/lib.js"></script></head></html>`
	srv := serve(t, false, page) // plain HTTP page: not "mixed"
	defer srv.Close()
	got, _ := MixedContent{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if len(got) != 0 {
		t.Fatalf("mixed content is only meaningful on HTTPS pages: %+v", got)
	}
}

func TestNoURL(t *testing.T) {
	for _, c := range []core.Check{MissingSRI{}, MixedContent{}} {
		got, err := c.Run(core.WithScanCache(context.Background()), core.Target{Repo: ".", Environment: core.EnvDev})
		if err != nil || got != nil {
			t.Fatalf("%s url-less: got=%v err=%v", c.ID(), got, err)
		}
	}
}
