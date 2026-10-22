package scout

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestDashboardServesEmbeddedApp(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	s := Mount(r, Config{AppName: "x"})
	defer s.Close(time.Second)

	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}

	// Index at the root, and for client-side routes (SPA fallback).
	for _, p := range []string{"/scout/ui/", "/scout/ui/findings", "/scout/ui/settings/deep/link"} {
		w := get(p)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<div id="root">`) {
			t.Fatalf("%s: status %d, body %.80q", p, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("%s: index must not be cached", p)
		}
	}

	// A hashed asset referenced by index.html is served with long caching.
	body := get("/scout/ui/").Body.String()
	i := strings.Index(body, "/scout/ui/assets/")
	if i < 0 {
		t.Fatal("index.html references no assets")
	}
	asset := body[i : i+strings.IndexAny(body[i:], `"'`)]
	w := get(asset)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("%s: status %d cache %q", asset, w.Code, w.Header().Get("Cache-Control"))
	}

	// /scout/ui redirects to the trailing-slash path.
	if w := get("/scout/ui"); w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/scout/ui/" {
		t.Fatalf("redirect: %d %q", w.Code, w.Header().Get("Location"))
	}

	// Path traversal cannot escape the embedded FS: it falls back to index.
	if w := get("/scout/ui/../../go.mod"); strings.Contains(w.Body.String(), "module github.com") {
		t.Fatal("path traversal served a file outside the dashboard")
	}
}
