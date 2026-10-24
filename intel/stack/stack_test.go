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
