package stack

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func has(cs []core.StackComponent, kind, name string) bool {
	for _, c := range cs {
		if c.Kind == kind && c.Name == name {
			return true
		}
	}
	return false
}

func TestDetectFromRepo(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"dependencies":{"next":"16.4.2","react":"19.3.1"},"devDependencies":{"typescript":"5.4.0"}}`)
	write("go.mod", "module x\n\nrequire github.com/gin-gonic/gin v1.9.1\n")

	got := Detect(core.Target{Repo: dir, Environment: core.EnvDev}, nil)
	if !has(got, "language", "JavaScript/TypeScript") || !has(got, "language", "Go") {
		t.Errorf("languages not detected: %+v", got)
	}
	if !has(got, "language", "TypeScript") {
		t.Error("TypeScript not detected")
	}
	if !has(got, "framework", "Next.js") || !has(got, "framework", "React") || !has(got, "framework", "Gin") {
		t.Errorf("frameworks not detected: %+v", got)
	}
	for _, c := range got {
		if c.Name == "Next.js" && c.Version != "16.4.2" {
			t.Errorf("Next.js version = %q", c.Version)
		}
	}
}

func TestDetectGrit(t *testing.T) {
	dir := t.TempDir()
	// A Grit monorepo is marked by grit.json in the root.
	body := `{"architecture":"triple","frontend":"next","version":"3.410.1","apps":{"expo":true,"desktop":true,"docs":true}}`
	if err := os.WriteFile(filepath.Join(dir, "grit.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got := Detect(core.Target{Repo: dir, Environment: core.EnvDev}, nil)
	if !has(got, "framework", "Grit (triple)") {
		t.Errorf("Grit not detected as first-class framework: %+v", got)
	}
	for _, c := range got {
		if c.Name == "Grit (triple)" && c.Version != "3.410.1" {
			t.Errorf("Grit version = %q, want 3.410.1", c.Version)
		}
	}
	// Grit's monorepo stack: a Go API and a Next.js/React frontend.
	if !has(got, "language", "Go") || !has(got, "language", "TypeScript") {
		t.Errorf("Grit sub-stack languages not detected: %+v", got)
	}
	if !has(got, "framework", "Next.js") || !has(got, "framework", "React") {
		t.Errorf("Grit frontend frameworks not detected: %+v", got)
	}
}

func TestDetectExpo(t *testing.T) {
	// Expo app: package.json has the expo dependency (with version) and eas.json
	// marks the root.
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"dependencies":{"expo":"~54.0.0","react-native":"0.79.0","expo-router":"~6.0.0"}}`)
	write("eas.json", `{"cli":{"version":">= 16.0.0"}}`)

	got := Detect(core.Target{Repo: dir, Environment: core.EnvDev}, nil)
	if !has(got, "framework", "Expo") {
		t.Errorf("Expo not detected: %+v", got)
	}
	if !has(got, "framework", "React Native") {
		t.Errorf("React Native not detected: %+v", got)
	}
	for _, c := range got {
		if c.Name == "Expo" && c.Version != "54.0.0" {
			t.Errorf("Expo version = %q, want 54.0.0 (from package.json)", c.Version)
		}
	}

	// eas.json alone (no expo dependency) still identifies an Expo app.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "eas.json"), []byte(`{"build":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !has(Detect(core.Target{Repo: dir2, Environment: core.EnvDev}, nil), "framework", "Expo") {
		t.Error("Expo not detected from eas.json alone")
	}
}

func TestDetectLaravel(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A Laravel + Inertia + React starter (composer.json carries the version;
	// artisan is the console script).
	write("composer.json", `{"require":{"php":"^8.2","laravel/framework":"^12.0","inertiajs/inertia-laravel":"^2.0"}}`)
	write("artisan", "#!/usr/bin/env php\n")
	write("package.json", `{"dependencies":{"react":"19.0.0"}}`)

	got := Detect(core.Target{Repo: dir, Environment: core.EnvDev}, nil)
	if !has(got, "framework", "Laravel") {
		t.Fatalf("Laravel not detected: %+v", got)
	}
	if !has(got, "language", "PHP") || !has(got, "framework", "React") {
		t.Errorf("Laravel+React stack not detected: %+v", got)
	}
	for _, c := range got {
		if c.Name == "Laravel" && c.Version != "12.0" {
			t.Errorf("Laravel version = %q, want 12.0 (from composer.json)", c.Version)
		}
	}

	// artisan alone (composer.json missing/unparseable) still identifies Laravel.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "artisan"), []byte("#!php\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !has(Detect(core.Target{Repo: dir2, Environment: core.EnvDev}, nil), "framework", "Laravel") {
		t.Error("Laravel not detected from artisan alone")
	}
}

func TestDetectFromFindings(t *testing.T) {
	findings := []core.Finding{
		{CheckID: "app.version-disclosure", Evidence: core.Evidence{Matched: "Server: nginx/1.18.0"}},
		{CheckID: "app.version-disclosure", Evidence: core.Evidence{Matched: "X-Powered-By: Next.js"}},
	}
	got := Detect(core.Target{Environment: core.EnvDev}, findings)
	if !has(got, "server", "nginx") {
		t.Errorf("server not detected: %+v", got)
	}
	if !has(got, "framework", "Next.js") {
		t.Errorf("X-Powered-By framework not detected: %+v", got)
	}
}
