package framework

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

func TestWordPressProbes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><link rel="stylesheet" href="/wp-content/themes/x/style.css"></html>`))
		case "/wp-json/wp/v2/users":
			_, _ = w.Write([]byte(`[{"id":1,"slug":"admin","name":"Admin"}]`))
		case "/xmlrpc.php":
			_, _ = w.Write([]byte("XML-RPC server accepts POST requests only."))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	got, err := Exposure{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	titles := titlesOf(got)
	if !has(titles, "user list") {
		t.Errorf("missing WordPress user enumeration finding: %v", titles)
	}
	if !has(titles, "XML-RPC") {
		t.Errorf("missing XML-RPC finding: %v", titles)
	}
}

func TestSpringActuator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "abc"})
			_, _ = w.Write([]byte("<html>app</html>"))
			return
		}
		if r.URL.Path == "/actuator/env" {
			_, _ = w.Write([]byte(`{"activeProfiles":["prod"],"propertySources":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	got, err := Exposure{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if !has(titlesOf(got), "actuator exposed: env") {
		t.Errorf("missing Spring actuator env finding: %v", titlesOf(got))
	}
	for _, f := range got {
		if f.Severity != core.SeverityHigh {
			t.Errorf("actuator env should be high: %+v", f)
		}
	}
}

func TestNoFrameworkNoProbes(t *testing.T) {
	// A plain app with no framework markers: nothing is probed/flagged.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("<html>hello</html>"))
			return
		}
		// Even if these existed, they must not be probed without detection.
		_, _ = w.Write([]byte(`{"activeProfiles":[]}`))
	}))
	defer srv.Close()
	got, _ := Exposure{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if len(got) != 0 {
		t.Fatalf("no framework detected, expected no findings, got %+v", got)
	}
}

func TestNoURL(t *testing.T) {
	got, err := Exposure{}.Run(core.WithScanCache(context.Background()), core.Target{Repo: ".", Environment: core.EnvDev})
	if err != nil || got != nil {
		t.Fatalf("url-less: %v %v", got, err)
	}
}

func titlesOf(fs []core.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Title
	}
	return out
}

func has(titles []string, sub string) bool {
	for _, t := range titles {
		if strings.Contains(t, sub) {
			return true
		}
	}
	return false
}
