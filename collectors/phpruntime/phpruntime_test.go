package phpruntime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func TestPhp2shellVulnerable(t *testing.T) {
	cases := []struct {
		ver  string
		want bool
	}{
		{"8.2.10", true},  // below 8.2.35
		{"8.2.35", false}, // fixed
		{"8.3.30", true},  // below 8.3.36
		{"8.4.27", false}, // fixed
		{"8.5.12", false}, // fixed
		{"8.5.0", true},   // below 8.5.12
		{"8.1.20", true},  // EOL branch
		{"7.4.33", true},  // EOL branch
		{"8.6.0", false},  // newer branch, assume patched
		{"8.2", false},    // branch only, patch unknown -> don't guess
	}
	for _, c := range cases {
		h, ok := parsePHP("PHP/"+c.ver, "test")
		if !ok {
			t.Fatalf("parsePHP failed for %q", c.ver)
		}
		if got, _ := php2shellVulnerable(h); got != c.want {
			t.Errorf("php2shellVulnerable(%q) = %v, want %v", c.ver, got, c.want)
		}
	}
}

func TestRunFromHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.10")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	ctx := core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
	got, err := PHP2Shell{}.Run(ctx, core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Severity != core.SeverityCritical {
		t.Errorf("severity = %v, want critical", f.Severity)
	}
	if !strings.Contains(f.Location, "CVE-2026-109618") {
		t.Errorf("location = %q", f.Location)
	}
	if !strings.Contains(f.Title, "8.2.10") {
		t.Errorf("title = %q", f.Title)
	}
}

func TestRunPatchedHeaderNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3.36")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	ctx := core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
	got, _ := PHP2Shell{}.Run(ctx, core.Target{URL: srv.URL, Environment: core.EnvDev})
	if len(got) != 0 {
		t.Fatalf("patched PHP should produce no finding, got %+v", got)
	}
}

func TestRunFromDockerfile(t *testing.T) {
	dir := t.TempDir()
	df := "FROM php:8.2.10-fpm-alpine\nRUN echo hi\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := PHP2Shell{}.Run(core.WithScanCache(context.Background()), core.Target{Repo: dir, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding from Dockerfile, got %d: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Evidence.Matched, "Dockerfile") {
		t.Errorf("evidence should cite the Dockerfile: %q", got[0].Evidence.Matched)
	}
}
