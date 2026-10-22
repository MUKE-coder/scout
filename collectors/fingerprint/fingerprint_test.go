package fingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func scanCtx(srv *httptest.Server) context.Context {
	return core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
}

func target(srv *httptest.Server) core.Target {
	return core.Target{URL: srv.URL, Environment: core.EnvDev}
}

func TestVersionDisclosure(t *testing.T) {
	t.Run("version header is medium", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "nginx/1.18.0")
			w.Header().Set("X-Powered-By", "PHP/7.4.3")
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		got, err := VersionDisclosure{}.Run(scanCtx(srv), target(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("want 2 findings, got %d: %+v", len(got), got)
		}
		for _, f := range got {
			if f.Severity != core.SeverityMedium {
				t.Errorf("%s: want medium (has version), got %v", f.Location, f.Severity)
			}
			if f.CWE[0] != "CWE-200" || f.Confidence != core.ConfidenceConfirmed {
				t.Errorf("unexpected finding: %+v", f)
			}
		}
	})

	t.Run("name without version is low", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Powered-By", "Next.js") // no version
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		got, _ := VersionDisclosure{}.Run(scanCtx(srv), target(srv))
		if len(got) != 1 || got[0].Severity != core.SeverityLow {
			t.Fatalf("want 1 low finding, got %+v", got)
		}
	})

	t.Run("no banner is clean", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		// httptest sets no Server header by default via the handler, but Go's
		// server may add Date only; ensure no banner headers are present.
		got, _ := VersionDisclosure{}.Run(scanCtx(srv), target(srv))
		if len(got) != 0 {
			t.Fatalf("clean app flagged: %+v", got)
		}
	})
}

func TestDirectoryListing(t *testing.T) {
	t.Run("apache autoindex flagged", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/uploads/" {
				_, _ = w.Write([]byte("<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1></body></html>"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		got, err := DirectoryListing{}.Run(scanCtx(srv), target(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Location != "/uploads/" || got[0].CWE[0] != "CWE-548" {
			t.Fatalf("want 1 /uploads/ finding, got %+v", got)
		}
	})

	t.Run("no listing is clean", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		got, _ := DirectoryListing{}.Run(scanCtx(srv), target(srv))
		if len(got) != 0 {
			t.Fatalf("clean app flagged: %+v", got)
		}
	})

	t.Run("200 without listing signature is clean", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<html>normal page, no listing</html>"))
		}))
		defer srv.Close()
		got, _ := DirectoryListing{}.Run(scanCtx(srv), target(srv))
		if len(got) != 0 {
			t.Fatalf("200 page without a listing signature should be clean: %+v", got)
		}
	})
}

func TestNoURL(t *testing.T) {
	for _, c := range []core.Check{VersionDisclosure{}, DirectoryListing{}} {
		got, err := c.Run(core.WithScanCache(context.Background()), core.Target{Repo: ".", Environment: core.EnvDev})
		if err != nil || got != nil {
			t.Fatalf("%s url-less: got=%v err=%v", c.ID(), got, err)
		}
	}
}

func TestMetadataDistinct(t *testing.T) {
	ids := map[string]bool{}
	for _, c := range []core.Check{VersionDisclosure{}, DirectoryListing{}} {
		if c.ID() == "" || ids[c.ID()] {
			t.Fatalf("bad/duplicate id %q", c.ID())
		}
		ids[c.ID()] = true
		if c.Category() != core.CategoryApp || c.Mode() != core.ModeSafe {
			t.Errorf("%s: category/mode wrong", c.ID())
		}
		if !strings.HasPrefix(c.ID(), "app.") {
			t.Errorf("%s: want app.* id", c.ID())
		}
	}
}
