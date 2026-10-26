package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func repoWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func run(t *testing.T, dir string) []core.Finding {
	t.Helper()
	got, err := Scanner{}.Run(context.Background(), core.Target{Repo: dir, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestDetectsSecrets(t *testing.T) {
	dir := repoWith(t, map[string]string{
		".env":                 "DB_PASSWORD=\"s3cret-production-pw\"\nAPP_NAME=todo\n",
		"deploy/key.pem":       "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n",
		"config.go":            "const awsKey = \"AKIA1234567890ABCDEF\"\n",
		"node_modules/leak.js": "const stripe = \"sk_live_abcdefghijklmnop1234\"", // skipped dir
	})
	got := run(t, dir)

	byRule := map[string]core.Finding{}
	for _, f := range got {
		byRule[f.Location] = f
		if !f.Evidence.Redacted {
			t.Errorf("evidence must be redacted: %+v", f.Evidence)
		}
	}
	if _, ok := byRule["private-key"]; !ok {
		t.Error("missed private key")
	}
	if _, ok := byRule["aws-access-key"]; !ok {
		t.Error("missed AWS key")
	}
	if _, ok := byRule["generic-secret"]; !ok {
		t.Error("missed .env password")
	}
	// node_modules must be skipped.
	for _, f := range got {
		if strings.Contains(f.Asset.File, "node_modules") {
			t.Error("scanned a skipped directory")
		}
		// The raw secret value must never appear in evidence.
		if strings.Contains(f.Evidence.ConfigLine, "s3cret-production-pw") || strings.Contains(f.Evidence.Matched, "AKIA1234567890ABCDEF") {
			t.Errorf("unmasked secret leaked in evidence: %+v", f.Evidence)
		}
	}
	// Every secret finding is tagged for the exposed-secret grade cap.
	for _, f := range got {
		if !f.HasTag(core.TagExposedSecret) {
			t.Errorf("%s not tagged exposed-secret", f.Location)
		}
	}
}

func TestIgnoresPlaceholders(t *testing.T) {
	dir := repoWith(t, map[string]string{
		".env.example": "DB_PASSWORD=\"changeme\"\nAPI_KEY=\"your-api-key-here\"\nSECRET=\"${VAULT_SECRET}\"\n",
		"readme.md":    "Set password = \"example-password\" before running.",
	})
	if got := run(t, dir); len(got) != 0 {
		t.Fatalf("placeholders should not be flagged: %+v", got)
	}
}

// From GitHub issue #6: a route constant whose key contains PASSWORD is not a
// secret, and a line annotated #nosec was already reviewed.
func TestGenericSecretFalsePositives(t *testing.T) {
	dir := repoWith(t, map[string]string{
		"routes.ts": "export const FORGOT_PASSWORD = \"/api/auth/forgot-password\"\n" +
			"export const RESET_PASSWORD = \"/api/auth/reset-password\"\n",
		"seed.go": "password = \"admin123dev\" // #nosec G101 -- guarded dev-only default\n",
	})
	if got := run(t, dir); len(got) != 0 {
		t.Fatalf("route constants and #nosec lines should not be flagged: %+v", got)
	}
}

// Weak-pattern secrets in test files are fixtures and are skipped (GitHub issue
// #7); strong cloud-key patterns still report even in a test file.
func TestTestFixturesSkipped(t *testing.T) {
	dir := repoWith(t, map[string]string{
		"api/user_test.go": "package api\n\nfunc login() {\n\tpassword := \"hunter2hunter2\"\n\t_ = password\n}\n", // weak pattern, test path → skipped
		"deploy/key.pem":   "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
		"api/key_test.go":  "const k = \"AKIA1234567890ABCDEF\"\n", // strong pattern, even in a test → reported
	})
	got := run(t, dir)
	by := map[string]core.Finding{}
	for _, f := range got {
		by[f.Asset.File] = f
	}
	// The generic secret in a *_test.go is a fixture: no finding at all.
	if _, ok := by["api/user_test.go"]; ok {
		t.Fatalf("weak secret in a test file should be skipped: %+v", by["api/user_test.go"])
	}
	// A private key and an AWS key stay strong even in a test file.
	if f := by["deploy/key.pem"]; f.Severity != core.SeverityCritical || !f.HasTag(core.TagExposedSecret) {
		t.Fatalf("private key must stay critical: %+v", f)
	}
	if f := by["api/key_test.go"]; f.Severity != core.SeverityHigh || !f.HasTag(core.TagExposedSecret) {
		t.Fatalf("AWS key must stay high even in a test: %+v", f)
	}
}

// From GitHub issue #7: a value that is an env-var NAME is a reference, not a
// secret.
func TestEnvVarNameNotSecret(t *testing.T) {
	dir := repoWith(t, map[string]string{
		"cfg.go": "cfg := Config{SecretEnv: \"UNUSED_SECRET\"}\n",
	})
	if got := run(t, dir); len(got) != 0 {
		t.Fatalf("an env-var name should not be flagged as a secret: %+v", got)
	}
}

func TestNoRepoNoFindings(t *testing.T) {
	if got, err := (Scanner{}).Run(context.Background(), core.Target{URL: "https://x.example", Environment: core.EnvDev}); err != nil || got != nil {
		t.Fatalf("url-only target: %v %v", got, err)
	}
}
