package exposure

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

func target(srv *httptest.Server) core.Target {
	return core.Target{URL: srv.URL, Environment: core.EnvProd}
}

// routes maps a request path to a canned response.
type route struct {
	status      int
	contentType string
	body        string
}

func serve(t *testing.T, routes map[string]route) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if rt.contentType != "" {
			w.Header().Set("Content-Type", rt.contentType)
		}
		w.WriteHeader(rt.status)
		_, _ = w.Write([]byte(rt.body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDotEnv(t *testing.T) {
	t.Run("exposed with secrets is critical", func(t *testing.T) {
		srv := serve(t, map[string]route{
			"/.env": {200, "text/plain", "DB_HOST=db\nDATABASE_URL=postgres://u:p@db/x\nSECRET_KEY=abc123\n"},
		})
		got, err := DotEnv{}.Run(scanCtx(srv), target(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if got[0].Severity != core.SeverityCritical {
			t.Errorf("severity = %s, want critical", got[0].Severity)
		}
		if !got[0].HasTag(core.TagExposedSecret) {
			t.Error("missing TagExposedSecret")
		}
		if !got[0].Evidence.Redacted {
			t.Error("evidence should be redacted")
		}
	})
	t.Run("spa 200 html is not a hit", func(t *testing.T) {
		srv := serve(t, map[string]route{
			"/.env": {200, "text/html", "<!doctype html><html><body>app</body></html>"},
		})
		got, err := DotEnv{}.Run(scanCtx(srv), target(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("want 0 findings for SPA html, got %d", len(got))
		}
	})
	t.Run("not present", func(t *testing.T) {
		srv := serve(t, map[string]route{})
		got, err := DotEnv{}.Run(scanCtx(srv), target(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("want 0 findings, got %d", len(got))
		}
	})
}

func TestGit(t *testing.T) {
	t.Run("exposed", func(t *testing.T) {
		srv := serve(t, map[string]route{
			"/.git/config": {200, "text/plain", "[core]\n\trepositoryformatversion = 0\n"},
		})
		got, err := Git{}.Run(scanCtx(srv), target(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Severity != core.SeverityHigh {
			t.Fatalf("want 1 high finding, got %+v", got)
		}
	})
	t.Run("absent", func(t *testing.T) {
		srv := serve(t, map[string]route{})
		got, _ := Git{}.Run(scanCtx(srv), target(srv))
		if len(got) != 0 {
			t.Fatalf("want 0, got %d", len(got))
		}
	})
}

func TestSwagger(t *testing.T) {
	srv := serve(t, map[string]route{
		"/swagger.json": {200, "application/json", `{"swagger":"2.0","paths":{}}`},
	})
	got, err := Swagger{}.Run(scanCtx(srv), target(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
}

func TestMetrics(t *testing.T) {
	t.Run("prometheus format", func(t *testing.T) {
		srv := serve(t, map[string]route{
			"/metrics": {200, "text/plain", "# HELP x\n# TYPE x counter\nx 1\n"},
		})
		got, err := Metrics{}.Run(scanCtx(srv), target(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Severity != core.SeverityMedium {
			t.Fatalf("want 1 medium finding, got %+v", got)
		}
	})
	t.Run("html page is not metrics", func(t *testing.T) {
		srv := serve(t, map[string]route{
			"/metrics": {200, "text/html", "<html>not metrics</html>"},
		})
		got, _ := Metrics{}.Run(scanCtx(srv), target(srv))
		if len(got) != 0 {
			t.Fatalf("want 0, got %d", len(got))
		}
	})
}

func TestBackupFiles(t *testing.T) {
	srv := serve(t, map[string]route{
		"/backup.sql": {200, "application/octet-stream", "-- MySQL dump\nCREATE TABLE users (...);"},
	})
	got, err := BackupFiles{}.Run(scanCtx(srv), target(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if got[0].Location != "/backup.sql" {
		t.Errorf("location = %q, want /backup.sql", got[0].Location)
	}
	if !got[0].Evidence.Redacted {
		t.Error("backup evidence should be redacted")
	}
}

func TestDirListing(t *testing.T) {
	srv := serve(t, map[string]route{
		"/uploads/": {200, "text/html", "<html><head><title>Index of /uploads</title></head><body><pre>Index of /uploads/</pre></body></html>"},
	})
	got, err := DirListing{}.Run(scanCtx(srv), target(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
}

func TestDashboards(t *testing.T) {
	t.Run("open dashboard: ui shell + unauthenticated api", func(t *testing.T) {
		srv := serve(t, map[string]route{
			"/sentinel/ui":         {200, "text/html", "<html><title>Sentinel Dashboard</title></html>"},
			"/sentinel/api/health": {200, "application/json", `{"status":"ok"}`},
		})
		got, err := Dashboards{}.Run(scanCtx(srv), target(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Location != "/sentinel/ui" {
			t.Fatalf("want 1 finding for /sentinel/ui, got %+v", got)
		}
	})
	t.Run("login shell but protected api is clean (issue #3)", func(t *testing.T) {
		// The HTML shell is public (that is how the login screen loads); the API
		// requires a session. This must NOT be a finding.
		srv := serve(t, map[string]route{
			"/scout/ui/":          {200, "text/html", "<html><title>Scout</title></html>"},
			"/scout/api/overview": {401, "application/json", `{"error":"authentication required"}`},
		})
		got, _ := Dashboards{}.Run(scanCtx(srv), target(srv))
		if len(got) != 0 {
			t.Fatalf("want 0 findings when the API is protected, got %+v", got)
		}
	})
	t.Run("a missing product does not hide the others (issue #3)", func(t *testing.T) {
		// Pulse is not mounted (probed first); Scout is mounted and exposed. The
		// check must still reach and report Scout.
		srv := serve(t, map[string]route{
			"/scout/ui/":          {200, "text/html", "<html><title>Scout</title></html>"},
			"/scout/api/overview": {200, "application/json", `{"grade":"A"}`},
		})
		got, _ := Dashboards{}.Run(scanCtx(srv), target(srv))
		if len(got) != 1 || got[0].Location != "/scout/ui/" {
			t.Fatalf("want 1 finding for /scout/ui/, got %+v", got)
		}
	})
}

func TestRepoOnlyTargetNoFindings(t *testing.T) {
	ctx := core.WithScanCache(context.Background())
	tgt := core.Target{Repo: ".", Environment: core.EnvDev}
	for _, c := range []core.Check{
		DotEnv{}, Git{}, Swagger{}, Metrics{}, BackupFiles{}, DirListing{}, Dashboards{},
	} {
		got, err := c.Run(ctx, tgt)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.ID(), err)
		}
		if len(got) != 0 {
			t.Errorf("%s: want 0 findings on repo-only target, got %d", c.ID(), len(got))
		}
	}
}
