package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout"
	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/report"
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
	if !strings.Contains(out, "effective safe") || !strings.Contains(out, "No checks were run") {
		t.Fatalf("prod dry-run should cap active to safe, got %q", out)
	}
	// A local target needs no ownership proof, so the opt-in alone allows active.
	out, _ = run("scan", "--target", "http://localhost:1", "--mode", "active", "--env", "prod", "--allow-active", "--dry-run")
	if !strings.Contains(out, "effective active") {
		t.Fatalf("--allow-active should permit active in prod, got %q", out)
	}
}

func TestScanRunsEngine(t *testing.T) {
	db := filepath.Join(t.TempDir(), "scout.db")
	out, err := run("scan", "--target", "http://localhost:1", "--mode", "safe", "--db", db, "--color", "never")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "mode safe") || !strings.Contains(out, "Grade") {
		t.Fatalf("terminal report missing: %q", out)
	}
	if _, err := os.Stat(db); err != nil {
		t.Fatalf("scan was not persisted: %v", err)
	}
}

func TestScanJSONAndSARIF(t *testing.T) {
	sarif := filepath.Join(t.TempDir(), "out.sarif")
	out, err := run("scan", "--target", "http://localhost:1", "--db", "", "--json", "--sarif", sarif)
	if err != nil {
		t.Fatal(err)
	}
	var doc report.Document
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, out)
	}
	if doc.Tool != "scout" || len(doc.Results) != 1 {
		t.Fatalf("doc = %+v", doc)
	}
	raw, err := os.ReadFile(sarif)
	if err != nil || !strings.Contains(string(raw), `"version": "2.1.0"`) {
		t.Fatalf("SARIF not written: %v", err)
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

func TestOwnershipToken(t *testing.T) {
	out, err := run("ownership", "-t", "https://shop.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "_scout-verify.shop.example.com") || !strings.Contains(out, "/.well-known/scout-verify.txt") {
		t.Fatalf("missing instructions: %q", out)
	}
	out, _ = run("ownership", "-t", "http://localhost:8080")
	if !strings.Contains(out, "no ownership proof is needed") {
		t.Fatalf("local target: %q", out)
	}
}

func TestOwnershipTokenUsesSigningKey(t *testing.T) {
	unkeyed, _ := run("ownership", "-t", "https://shop.example.com")
	t.Setenv("SCOUT_SIGNING_KEY", "install-secret")
	keyed, _ := run("ownership", "-t", "https://shop.example.com")
	want := engine.OwnershipToken([]byte("install-secret"), "shop.example.com")
	if !strings.Contains(keyed, want) || unkeyed == keyed {
		t.Fatalf("token must match the signing key scans verify with:\n%s", keyed)
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
