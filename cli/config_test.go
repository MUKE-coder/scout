package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanReadsConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "scout.yaml")
	yaml := "environment: prod\nmode: active\ntargets:\n  - name: local\n    url: http://localhost:1\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	// From the file: prod caps active to safe.
	out, err := run("scan", "--config", cfgPath, "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Plan for local (prod)") || !strings.Contains(out, "effective safe") {
		t.Fatalf("config file not applied:\n%s", out)
	}

	// Env overrides the file.
	t.Setenv("SCOUT_ENV", "dev")
	out, _ = run("scan", "--config", cfgPath, "--dry-run")
	if !strings.Contains(out, "(dev)") || !strings.Contains(out, "effective active") {
		t.Fatalf("SCOUT_ENV not applied:\n%s", out)
	}

	// Flags override env.
	out, _ = run("scan", "--config", cfgPath, "--env", "staging", "--mode", "passive", "--dry-run")
	if !strings.Contains(out, "(staging)") || !strings.Contains(out, "effective passive") {
		t.Fatalf("flags not applied:\n%s", out)
	}

	// --target replaces the file's targets.
	out, _ = run("scan", "--config", cfgPath, "--target", "http://localhost:2", "--dry-run")
	if !strings.Contains(out, "Plan for http://localhost:2") || strings.Contains(out, "Plan for local") {
		t.Fatalf("--target should replace config targets:\n%s", out)
	}
}

func TestScanRejectsBadConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "scout.yaml")
	_ = os.WriteFile(cfgPath, []byte("scope:\n  hostz: [x]\n"), 0o600)
	if _, err := run("scan", "--config", cfgPath, "--target", "http://localhost:1", "--dry-run"); err == nil ||
		!strings.Contains(err.Error(), "hostz") {
		t.Fatalf("typo in config should be rejected, got %v", err)
	}
}
