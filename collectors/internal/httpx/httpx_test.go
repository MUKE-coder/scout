package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func TestGetMemoizesAndCapturesEvidence(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "x"})
		w.Header().Set("X-Test", "1")
		w.Write([]byte(strings.Repeat("a", 3000)))
	}))
	defer srv.Close()

	ctx := core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
	p1, err := Get(ctx, srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := Get(ctx, srv.URL+"/")
	if hits.Load() != 1 || p1 != p2 {
		t.Fatalf("not memoized: hits=%d", hits.Load())
	}
	if p1.Status != 200 || len(p1.Cookies) != 1 || p1.Header.Get("X-Test") != "1" {
		t.Fatalf("page = %+v", p1)
	}
	if !strings.Contains(p1.Request, "GET / HTTP/1.1") || !strings.Contains(p1.Response, "X-Test: 1") ||
		!strings.Contains(p1.Response, "bytes truncated") {
		t.Fatalf("evidence:\n%s\n%s", p1.Request, p1.Response)
	}
}

func TestGetWithoutGuardedClientRefuses(t *testing.T) {
	if _, err := Get(context.Background(), "http://localhost/"); err == nil {
		t.Fatal("expected refusal outside a scan")
	}
}

func TestAssetExposure(t *testing.T) {
	local := core.Target{URL: "http://localhost:8080"}
	u, _ := Resolve(local, "/a/b")
	a := Asset(local, u)
	if a.Exposure != core.ExposureInternal || a.Value != "http://localhost:8080/a/b" || a.Path != "/a/b" {
		t.Fatalf("asset = %+v", a)
	}
	remote := core.Target{URL: "https://example.com"}
	u, _ = Resolve(remote, "")
	if Asset(remote, u).Exposure != core.ExposureInternet {
		t.Fatal("remote should be internet-facing")
	}
}
