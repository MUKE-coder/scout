package infodisc

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

func TestVerboseErrorsDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("Error: boom\n    at Object.handler (/app/server.js:42:11)\n    at /app/next.js:10:5"))
	}))
	defer srv.Close()
	got, err := VerboseErrors{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || !strings.Contains(got[0].Title, "Node.js stack trace") {
		t.Fatalf("stack trace not detected: %+v", got)
	}
	if got[0].CWE[0] != "CWE-209" {
		t.Errorf("cwe = %v", got[0].CWE)
	}
}

func TestCleanAppNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer srv.Close()
	got, _ := VerboseErrors{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if len(got) != 0 {
		t.Fatalf("clean error page should not be flagged: %+v", got)
	}
}

func TestGraphQLIntrospection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.URL.Query().Get("query") != "" {
			w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	got, err := GraphQLIntrospection{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Location != "/graphql" {
		t.Fatalf("introspection not detected: %+v", got)
	}
}

func TestImproperAssetMgmt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both /api/v1/* and /api/v2/* are live; /v3 is not.
		if strings.HasPrefix(r.URL.Path, "/api/v1") || strings.HasPrefix(r.URL.Path, "/api/v2") {
			w.Write([]byte(`[]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	got, err := ImproperAssetMgmt{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Location != "/api/v1" {
		t.Fatalf("want v1 flagged, got %+v", got)
	}
}

func TestHostHeaderReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect the Host into a reset link (classic host-header injection).
		w.Write([]byte(`<a href="https://` + r.Host + `/reset?token=abc">reset</a>`))
	}))
	defer srv.Close()
	got, err := HostHeaderInjection{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CWE[0] != "CWE-644" {
		t.Fatalf("host header injection not detected: %+v", got)
	}
}

func TestHostHeaderCleanApp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<html>ok</html>`)) // does not reflect Host
	}))
	defer srv.Close()
	got, _ := HostHeaderInjection{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if len(got) != 0 {
		t.Fatalf("clean app should not be flagged: %+v", got)
	}
}

func TestNoURL(t *testing.T) {
	for _, c := range []core.Check{VerboseErrors{}, GraphQLIntrospection{}, ImproperAssetMgmt{}, HostHeaderInjection{}} {
		if got, err := c.Run(core.WithScanCache(context.Background()), core.Target{Repo: ".", Environment: core.EnvDev}); err != nil || got != nil {
			t.Fatalf("%s: %v %v", c.ID(), got, err)
		}
	}
}
