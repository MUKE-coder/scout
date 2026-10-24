package sca

import (
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"

	"github.com/MUKE-coder/scout/intel"
)

// parsers maps a manifest/lockfile base name to a parser. Lockfiles (exact,
// resolved versions) are preferred; a few manifests are parsed best-effort.
// To add an ecosystem, add a parser here — nothing else changes.
var parsers = map[string]func(rel string, data []byte) []intel.Package{
	"package-lock.json":  parseNpmLock,
	"go.mod":             parseGoMod,
	"requirements.txt":   parseRequirements,
	"poetry.lock":        parsePoetryLock,
	"Pipfile.lock":       parsePipfileLock,
	"composer.lock":      parseComposerLock,
	"Cargo.lock":         parseCargoLock,
	"Gemfile.lock":       parseGemfileLock,
	"packages.lock.json": parseNuGetLock,
	"pom.xml":            parsePom,
}

func dedupe(pkgs []intel.Package) []intel.Package {
	seen := map[string]bool{}
	out := pkgs[:0]
	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		k := p.Ecosystem + "\x00" + p.Name + "\x00" + p.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out
}

// ---- npm ------------------------------------------------------------------

func parseNpmLock(rel string, data []byte) []intel.Package {
	var lock struct {
		Packages     map[string]struct{ Version string } `json:"packages"`     // v2/v3
		Dependencies map[string]struct{ Version string } `json:"dependencies"` // v1
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	var out []intel.Package
	for path, p := range lock.Packages {
		if path == "" { // the root project
			continue
		}
		name := path
		if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
			name = path[i+len("node_modules/"):]
		}
		out = append(out, npmPkg(name, p.Version, rel))
	}
	if len(out) == 0 {
		for name, p := range lock.Dependencies {
			out = append(out, npmPkg(name, p.Version, rel))
		}
	}
	return out
}

func npmPkg(name, version, rel string) intel.Package {
	return intel.Package{Ecosystem: "npm", Name: name, Version: version, PURL: "pkg:npm/" + name + "@" + version, File: rel}
}

// ---- Go -------------------------------------------------------------------

var goRequire = regexp.MustCompile(`^\s*(?:require\s+)?([^\s]+)\s+v([^\s/]+)`)

func parseGoMod(rel string, data []byte) []intel.Package {
	var out []intel.Package
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || t == "" {
			continue
		}
		if strings.HasPrefix(t, "require (") {
			inBlock = true
			continue
		}
		if inBlock && t == ")" {
			inBlock = false
			continue
		}
		if !inBlock && !strings.HasPrefix(t, "require ") {
			continue
		}
		m := goRequire.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, version := m[1], m[2]
		out = append(out, intel.Package{Ecosystem: "Go", Name: name, Version: version, PURL: "pkg:golang/" + name + "@v" + version, File: rel})
	}
	return out
}

// ---- Python ---------------------------------------------------------------

var pyPin = regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._-]+)`)

func normalizePyPI(name string) string {
	return strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-"))
}

func pyPkg(name, version, rel string) intel.Package {
	n := normalizePyPI(name)
	return intel.Package{Ecosystem: "PyPI", Name: n, Version: version, PURL: "pkg:pypi/" + n + "@" + version, File: rel}
}

func parseRequirements(rel string, data []byte) []intel.Package {
	var out []intel.Package
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") {
			continue
		}
		if m := pyPin.FindStringSubmatch(t); m != nil {
			out = append(out, pyPkg(m[1], m[2], rel))
		}
	}
	return out
}

func parsePoetryLock(rel string, data []byte) []intel.Package {
	return parseTOMLPackages(rel, data, "PyPI", "pkg:pypi/", normalizePyPI)
}

func parsePipfileLock(rel string, data []byte) []intel.Package {
	var lock struct {
		Default map[string]struct{ Version string } `json:"default"`
		Develop map[string]struct{ Version string } `json:"develop"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	var out []intel.Package
	for _, group := range []map[string]struct{ Version string }{lock.Default, lock.Develop} {
		for name, p := range group {
			v := strings.TrimPrefix(p.Version, "==")
			if v != "" {
				out = append(out, pyPkg(name, v, rel))
			}
		}
	}
	return out
}

// ---- Composer / PHP -------------------------------------------------------

func parseComposerLock(rel string, data []byte) []intel.Package {
	var lock struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	var out []intel.Package
	for _, group := range [][]struct{ Name, Version string }{lock.Packages, lock.PackagesDev} {
		for _, p := range group {
			v := strings.TrimPrefix(p.Version, "v")
			out = append(out, intel.Package{Ecosystem: "Packagist", Name: p.Name, Version: v, PURL: "pkg:composer/" + p.Name + "@" + v, File: rel})
		}
	}
	return out
}

// ---- Cargo / Rust ---------------------------------------------------------

func parseCargoLock(rel string, data []byte) []intel.Package {
	return parseTOMLPackages(rel, data, "crates.io", "pkg:cargo/", func(s string) string { return s })
}

// ---- RubyGems -------------------------------------------------------------

var gemSpec = regexp.MustCompile(`^    ([A-Za-z0-9._-]+) \(([^)=<>~ ]+)\)$`)

func parseGemfileLock(rel string, data []byte) []intel.Package {
	var out []intel.Package
	for _, line := range strings.Split(string(data), "\n") {
		if m := gemSpec.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			out = append(out, intel.Package{Ecosystem: "RubyGems", Name: m[1], Version: m[2], PURL: "pkg:gem/" + m[1] + "@" + m[2], File: rel})
		}
	}
	return out
}

// ---- NuGet ----------------------------------------------------------------

func parseNuGetLock(rel string, data []byte) []intel.Package {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	var out []intel.Package
	for _, deps := range lock.Dependencies {
		for name, d := range deps {
			if d.Resolved != "" {
				out = append(out, intel.Package{Ecosystem: "NuGet", Name: name, Version: d.Resolved, PURL: "pkg:nuget/" + name + "@" + d.Resolved, File: rel})
			}
		}
	}
	return out
}

// ---- Maven (best-effort: literal versions only) ---------------------------

func parsePom(rel string, data []byte) []intel.Package {
	var pom struct {
		Dependencies struct {
			Dependency []struct {
				GroupID    string `xml:"groupId"`
				ArtifactID string `xml:"artifactId"`
				Version    string `xml:"version"`
			} `xml:"dependency"`
		} `xml:"dependencies"`
	}
	if xml.Unmarshal(data, &pom) != nil {
		return nil
	}
	var out []intel.Package
	for _, d := range pom.Dependencies.Dependency {
		if d.Version == "" || strings.Contains(d.Version, "${") {
			continue // unresolved property; needs full resolution
		}
		name := d.GroupID + ":" + d.ArtifactID
		out = append(out, intel.Package{Ecosystem: "Maven", Name: name, Version: d.Version, PURL: "pkg:maven/" + d.GroupID + "/" + d.ArtifactID + "@" + d.Version, File: rel})
	}
	return out
}

// ---- shared TOML [[package]] scanner (poetry.lock, Cargo.lock) ------------

var tomlName = regexp.MustCompile(`^name\s*=\s*"([^"]+)"`)
var tomlVer = regexp.MustCompile(`^version\s*=\s*"([^"]+)"`)

func parseTOMLPackages(rel string, data []byte, eco, purlPrefix string, norm func(string) string) []intel.Package {
	var out []intel.Package
	var name, version string
	flush := func() {
		if name != "" && version != "" {
			n := norm(name)
			out = append(out, intel.Package{Ecosystem: eco, Name: n, Version: version, PURL: purlPrefix + n + "@" + version, File: rel})
		}
		name, version = "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "[[package]]" {
			flush()
			continue
		}
		if m := tomlName.FindStringSubmatch(t); m != nil {
			name = m[1]
		} else if m := tomlVer.FindStringSubmatch(t); m != nil && version == "" {
			version = m[1]
		}
	}
	flush()
	return out
}
