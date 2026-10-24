// Package stack detects a target's technology stack — languages, frameworks,
// runtimes — from a repo's manifests and from a running app's fingerprint
// findings. The result drives stack-aware checks and the dashboard.
package stack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/MUKE-coder/scout/core"
)

// Detect returns the stack components for a target: from its repo manifests
// and from fingerprint findings (Server / X-Powered-By). Deterministic.
func Detect(t core.Target, findings []core.Finding) []core.StackComponent {
	var out []core.StackComponent
	if t.Repo != "" {
		out = append(out, fromRepo(t.Repo)...)
	}
	out = append(out, fromFindings(findings)...)
	return dedupe(out)
}

// manifest → language. Presence of the file implies the language.
var languageOf = map[string]string{
	"package.json": "JavaScript/TypeScript", "go.mod": "Go", "requirements.txt": "Python",
	"pyproject.toml": "Python", "Pipfile": "Python", "composer.json": "PHP", "Gemfile": "Ruby",
	"Cargo.toml": "Rust", "pom.xml": "Java", "build.gradle": "Java", "build.gradle.kts": "Kotlin",
	"pubspec.yaml": "Dart", "Package.swift": "Swift",
}

// framework dependency name → display name, per ecosystem key.
var frameworks = map[string]map[string]string{
	"js":   {"next": "Next.js", "react": "React", "vue": "Vue", "@angular/core": "Angular", "nuxt": "Nuxt", "svelte": "Svelte", "express": "Express", "@nestjs/core": "NestJS", "@remix-run/react": "Remix", "astro": "Astro"},
	"go":   {"github.com/gin-gonic/gin": "Gin", "github.com/labstack/echo": "Echo", "github.com/gofiber/fiber": "Fiber", "github.com/go-chi/chi": "Chi", "github.com/gorilla/mux": "Gorilla"},
	"py":   {"django": "Django", "flask": "Flask", "fastapi": "FastAPI", "tornado": "Tornado", "celery": "Celery"},
	"php":  {"laravel/framework": "Laravel", "symfony/symfony": "Symfony", "symfony/framework-bundle": "Symfony"},
	"rb":   {"rails": "Rails", "sinatra": "Sinatra", "hanami": "Hanami"},
	"rust": {"actix-web": "Actix Web", "axum": "Axum", "rocket": "Rocket"},
	"java": {"org.springframework.boot": "Spring Boot", "org.springframework": "Spring"},
}

func fromRepo(repoPath string) []core.StackComponent {
	var out []core.StackComponent
	add := func(c core.StackComponent) { out = append(out, c) }
	read := func(name string) ([]byte, bool) {
		b, err := os.ReadFile(filepath.Join(repoPath, name)) // #nosec G304 -- user's own repo
		return b, err == nil
	}

	for file, lang := range languageOf {
		if _, err := os.Stat(filepath.Join(repoPath, file)); err == nil {
			add(core.StackComponent{Kind: "language", Name: lang, Source: file})
		}
	}

	// JS/TS frameworks from package.json dependencies (with declared versions).
	if b, ok := read("package.json"); ok {
		var pj struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(b, &pj) == nil {
			deps := map[string]string{}
			for k, v := range pj.Dependencies {
				deps[k] = v
			}
			for k, v := range pj.DevDependencies {
				deps[k] = v
			}
			if _, ok := deps["typescript"]; ok {
				add(core.StackComponent{Kind: "language", Name: "TypeScript", Source: "package.json"})
			}
			for dep, name := range frameworks["js"] {
				if v, ok := deps[dep]; ok {
					add(core.StackComponent{Kind: "framework", Name: name, Version: cleanVer(v), Source: "package.json"})
				}
			}
		}
	}
	// Go frameworks from go.mod require lines.
	if b, ok := read("go.mod"); ok {
		text := string(b)
		for mod, name := range frameworks["go"] {
			re := regexp.MustCompile(regexp.QuoteMeta(mod) + `\S*\s+v([0-9][^\s]*)`)
			if m := re.FindStringSubmatch(text); m != nil {
				add(core.StackComponent{Kind: "framework", Name: name, Version: m[1], Source: "go.mod"})
			}
		}
	}
	// Python frameworks from requirements.txt / pyproject.
	for _, f := range []string{"requirements.txt", "pyproject.toml", "poetry.lock"} {
		if b, ok := read(f); ok {
			low := strings.ToLower(string(b))
			for dep, name := range frameworks["py"] {
				if strings.Contains(low, dep) {
					add(core.StackComponent{Kind: "framework", Name: name, Source: f})
				}
			}
		}
	}
	// PHP / Ruby / Rust / Java frameworks by substring in their manifest.
	byFile := map[string]string{"composer.json": "php", "Gemfile": "rb", "Cargo.toml": "rust", "pom.xml": "java", "build.gradle": "java"}
	for file, key := range byFile {
		if b, ok := read(file); ok {
			text := string(b)
			for dep, name := range frameworks[key] {
				if strings.Contains(text, dep) {
					add(core.StackComponent{Kind: "framework", Name: name, Source: file})
				}
			}
		}
	}
	return out
}

// fromFindings reads the server/runtime banner from the version-disclosure
// finding's evidence (e.g. "Server: nginx/1.18" or "X-Powered-By: Next.js").
func fromFindings(findings []core.Finding) []core.StackComponent {
	var out []core.StackComponent
	for _, f := range findings {
		if f.CheckID != "app.version-disclosure" {
			continue
		}
		m := f.Evidence.Matched // e.g. "Server: nginx/1.18.0"
		header, value, ok := strings.Cut(m, ": ")
		if !ok {
			continue
		}
		name, version := value, ""
		if i := strings.IndexAny(value, "/ "); i >= 0 {
			name, version = value[:i], strings.TrimLeft(value[i:], "/ ")
		}
		kind := "server"
		if strings.EqualFold(header, "X-Powered-By") || strings.EqualFold(header, "X-Generator") {
			kind = "framework"
		}
		out = append(out, core.StackComponent{Kind: kind, Name: strings.TrimSpace(name), Version: strings.TrimSpace(version), Source: header + " header"})
	}
	return out
}

var verClean = regexp.MustCompile(`[0-9][0-9A-Za-z.\-]*`)

func cleanVer(v string) string {
	if m := verClean.FindString(v); m != "" {
		return m
	}
	return ""
}

func dedupe(cs []core.StackComponent) []core.StackComponent {
	seen := map[string]bool{}
	var out []core.StackComponent
	for _, c := range cs {
		if c.Name == "" {
			continue
		}
		k := c.Kind + "\x00" + strings.ToLower(c.Name)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return kindRank(out[i].Kind) < kindRank(out[j].Kind)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func kindRank(k string) int {
	switch k {
	case "language":
		return 0
	case "framework":
		return 1
	case "runtime":
		return 2
	case "server":
		return 3
	default:
		return 4
	}
}
