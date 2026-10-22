package config

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

// serve routes exact paths to canned responses.
type resp struct {
	status int
	ctype  string
	body   string
}

func serve(t *testing.T, routes map[string]resp) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rt, ok := routes[r.URL.Path]; ok {
			if rt.ctype != "" {
				w.Header().Set("Content-Type", rt.ctype)
			}
			w.WriteHeader(rt.status)
			_, _ = w.Write([]byte(rt.body))
			return
		}
		// default Gin-style 404
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func prodTarget(srv *httptest.Server) core.Target {
	return core.Target{URL: srv.URL, Environment: core.EnvProd}
}

func TestGinDebug(t *testing.T) {
	t.Run("default 404 in prod is medium", func(t *testing.T) {
		srv := serve(t, map[string]resp{}) // everything 404s with the Gin default body
		got, err := GinDebug{}.Run(scanCtx(srv), prodTarget(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Severity != core.SeverityMedium {
			t.Fatalf("want 1 medium, got %+v", got)
		}
	})
	t.Run("custom 404 is clean", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		}))
		t.Cleanup(srv.Close)
		got, err := GinDebug{}.Run(scanCtx(srv), prodTarget(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
}

func TestDefaultCreds(t *testing.T) {
	t.Run("login route in prod route table", func(t *testing.T) {
		srv := serve(t, map[string]resp{})
		tgt := prodTarget(srv)
		tgt.Routes = []core.Route{{Method: "POST", Path: "/sentinel/api/auth/login"}}
		got, err := DefaultCreds{}.Run(scanCtx(srv), tgt)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Location != "/sentinel/api/auth/login" {
			t.Fatalf("want 1 finding for login route, got %+v", got)
		}
		if got[0].Asset.Kind != core.AssetRoute {
			t.Errorf("asset kind = %s, want route", got[0].Asset.Kind)
		}
	})
	t.Run("dev environment is exempt", func(t *testing.T) {
		srv := serve(t, map[string]resp{})
		tgt := core.Target{URL: srv.URL, Environment: core.EnvDev,
			Routes: []core.Route{{Method: "POST", Path: "/sentinel/api/auth/login"}}}
		got, _ := DefaultCreds{}.Run(scanCtx(srv), tgt)
		if len(got) != 0 {
			t.Fatalf("want 0 in dev, got %+v", got)
		}
	})
	t.Run("no known login route", func(t *testing.T) {
		srv := serve(t, map[string]resp{})
		tgt := prodTarget(srv)
		tgt.Routes = []core.Route{{Method: "GET", Path: "/api/users"}}
		got, _ := DefaultCreds{}.Run(scanCtx(srv), tgt)
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
}

func TestSentinelMisconfig(t *testing.T) {
	t.Run("log-only waf flagged", func(t *testing.T) {
		srv := serve(t, map[string]resp{
			"/sentinel/api/health": {200, "application/json", `{"waf_mode":"log"}`},
		})
		got, err := SentinelMisconfig{}.Run(scanCtx(srv), prodTarget(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Severity != core.SeverityMedium {
			t.Fatalf("want 1 medium, got %+v", got)
		}
	})
	t.Run("blocking waf is clean", func(t *testing.T) {
		srv := serve(t, map[string]resp{
			"/sentinel/api/health": {200, "application/json", `{"waf_mode":"block"}`},
		})
		got, _ := SentinelMisconfig{}.Run(scanCtx(srv), prodTarget(srv))
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
	t.Run("no sentinel present", func(t *testing.T) {
		srv := serve(t, map[string]resp{})
		got, _ := SentinelMisconfig{}.Run(scanCtx(srv), prodTarget(srv))
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
}

func TestInMemoryStorageProd(t *testing.T) {
	t.Run("memory storage in prod", func(t *testing.T) {
		srv := serve(t, map[string]resp{
			"/sentinel/api/health": {200, "application/json", `{"storage":"memory"}`},
		})
		got, err := InMemoryStorageProd{}.Run(scanCtx(srv), prodTarget(srv))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %+v", got)
		}
	})
	t.Run("sqlite storage is clean", func(t *testing.T) {
		srv := serve(t, map[string]resp{
			"/sentinel/api/health": {200, "application/json", `{"storage":"sqlite"}`},
		})
		got, _ := InMemoryStorageProd{}.Run(scanCtx(srv), prodTarget(srv))
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
}

func TestRepoOnlyTargetNoFindings(t *testing.T) {
	ctx := core.WithScanCache(context.Background())
	tgt := core.Target{Repo: ".", Environment: core.EnvProd}
	for _, c := range []core.Check{
		GinDebug{}, DefaultCreds{}, SentinelMisconfig{}, PulseMisconfig{}, InMemoryStorageProd{},
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
