package dockerfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func scan(t *testing.T, name, body string) map[string]core.Finding {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Lint{}.Run(context.Background(), core.Target{Repo: dir, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]core.Finding{}
	for _, f := range got {
		by[f.Location] = f
	}
	return by
}

func TestInsecureDockerfile(t *testing.T) {
	by := scan(t, "Dockerfile", `FROM node:latest
ADD https://example.com/app.tar.gz /app
ENV API_KEY=realconfiguredkey123
RUN npm ci
CMD ["node","server.js"]
`)
	for _, want := range []string{"docker.unpinned-base", "docker.add-remote", "docker.env-secret", "docker.no-user"} {
		if _, ok := by[want]; !ok {
			t.Errorf("missed %s; got %v", want, keys(by))
		}
	}
	if by["docker.env-secret"].Severity != core.SeverityHigh {
		t.Error("env secret should be high")
	}
}

func TestSecureDockerfile(t *testing.T) {
	by := scan(t, "Dockerfile", `FROM golang:1.24.2@sha256:abc AS build
RUN adduser -D app
ENV APP_PORT=8080
USER app
CMD ["/app"]
`)
	if len(by) != 0 {
		t.Fatalf("a hardened Dockerfile should have no findings: %v", keys(by))
	}
}

func TestUserRootFlagged(t *testing.T) {
	by := scan(t, "Dockerfile", "FROM alpine:3.20\nUSER root\n")
	if _, ok := by["docker.user-root"]; !ok {
		t.Fatalf("USER root should be flagged: %v", keys(by))
	}
	if _, ok := by["docker.no-user"]; ok {
		t.Error("no-user should not also fire when USER root is present")
	}
}

func TestPlaceholderEnvIgnored(t *testing.T) {
	by := scan(t, "Dockerfile.dev", "FROM alpine:3.20\nUSER app\nENV API_KEY=your-api-key-here\n")
	if _, ok := by["docker.env-secret"]; ok {
		t.Error("placeholder env should not be flagged")
	}
}

func TestNonDockerfileIgnored(t *testing.T) {
	by := scan(t, "notes.txt", "FROM node:latest\nUSER root\n")
	if len(by) != 0 {
		t.Fatalf("non-Dockerfile should be ignored: %v", keys(by))
	}
}

func keys(m map[string]core.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
