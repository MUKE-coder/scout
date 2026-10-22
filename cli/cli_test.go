package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout"
)

func run(args ...string) (string, error) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestVersion(t *testing.T) {
	out, err := run("version")
	if err != nil || !strings.Contains(out, scout.Version) {
		t.Fatalf("version: %q, %v", out, err)
	}
}

func TestScanDryRun(t *testing.T) {
	out, err := run("scan", "--target", "https://example.com", "--mode", "active", "--env", "prod", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "effective safe") || !strings.Contains(out, "Nothing was sent") {
		t.Fatalf("prod dry-run should cap active to safe, got %q", out)
	}
	out, _ = run("scan", "--target", "https://example.com", "--mode", "active", "--env", "prod", "--allow-active", "--dry-run")
	if !strings.Contains(out, "effective active") {
		t.Fatalf("--allow-active should permit active in prod, got %q", out)
	}
}

func TestScanRunsEngine(t *testing.T) {
	out, err := run("scan", "--target", "http://localhost:1", "--mode", "safe")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "mode safe") {
		t.Fatalf("scan summary missing: %q", out)
	}
}

func TestFlagValidation(t *testing.T) {
	cases := [][]string{
		{"scan"}, // no target
		{"scan", "-t", "https://x.io", "-m", "loud"}, // bad mode
		{"scan", "-t", "https://x.io", "-e", "moon"}, // bad env
		{"scan", "-t", "notaurl"},                    // bad URL
		{"ci", "--repo", ".", "--fail-on", "spicy"},  // bad severity
		{"diff", "only-one"},                         // wrong arg count
	}
	for _, args := range cases {
		if _, err := run(args...); err == nil || strings.Contains(err.Error(), "not implemented") {
			t.Errorf("%v: expected validation error, got %v", args, err)
		}
	}
}

func TestDashboardURL(t *testing.T) {
	cases := map[string]string{
		":9090":          "http://localhost:9090/scout/ui/",
		"127.0.0.1:9191": "http://127.0.0.1:9191/scout/ui/",
		"0.0.0.0:80":     "http://localhost:80/scout/ui/",
	}
	for in, want := range cases {
		if got := dashboardURL(in); got != want {
			t.Errorf("dashboardURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCommandsExist(t *testing.T) {
	root := NewRootCmd()
	for _, name := range []string{"scan", "serve", "ci", "diff", "version"} {
		if c, _, err := root.Find([]string{name}); err != nil || c.Name() != name {
			t.Errorf("missing command %q", name)
		}
	}
}
