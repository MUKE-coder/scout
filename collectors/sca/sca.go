// Package sca performs Software Composition Analysis: it inventories a repo's
// dependencies across every major ecosystem (from lockfiles/manifests) and
// matches them against known vulnerabilities via the intel layer (OSV.dev,
// which aggregates NVD, GitHub Advisories, RustSec, PyPA, the Go vuln DB …).
//
// It degrades gracefully: no repo, no manifests, or an unreachable database all
// mean "report nothing" rather than failing the scan.
package sca

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/repo"
	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/intel"
)

func init() { core.Register(Deps{}) }

// db is the vulnerability source; a package var so tests can inject a fake.
var db intel.DB = intel.NewOSV()

// skipDirs are not walked: they hold dependencies' own manifests, which would
// double-count, and build output.
var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, "dist": true,
	".next": true, "target": true, "build": true, ".venv": true, "venv": true,
}

const maxManifest = 8 << 20 // 8 MiB

// Deps reports dependencies with known vulnerabilities.
type Deps struct{}

func (Deps) ID() string              { return "code.vulnerable-deps" }
func (Deps) Category() core.Category { return core.CategoryCode }
func (Deps) Mode() core.Mode         { return core.ModePassive }
func (Deps) Description() string {
	return "A dependency has a known vulnerability (software composition analysis)"
}
func (Deps) OWASP() []string { return []string{"A06:2021"} }
func (Deps) ASVS() []string  { return []string{"V14.2.1"} }

func (Deps) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	root := repo.Base(t.Repo)
	if root == "" {
		return nil, nil
	}
	pkgs := inventory(root)
	if len(pkgs) == 0 {
		return nil, nil
	}
	results, err := db.Query(ctx, pkgs)
	if err != nil {
		return nil, nil // database unreachable — skip, don't fail the scan
	}

	var out []core.Finding
	seen := map[string]bool{}
	for i, vulns := range results {
		if i >= len(pkgs) {
			break
		}
		p := pkgs[i]
		for _, v := range vulns {
			key := p.Ecosystem + p.Name + p.Version + v.ID
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, finding(t, p, v))
		}
	}
	// Deterministic order: worst first, then by package.
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Severity != out[b].Severity {
			return out[a].Severity > out[b].Severity
		}
		return out[a].Asset.Value < out[b].Asset.Value
	})
	return out, nil
}

func finding(t core.Target, p intel.Package, v intel.Vuln) core.Finding {
	sev, conf := severity(v.Severity)
	id := v.ID
	if len(v.Aliases) > 0 {
		id = strings.Join(append([]string{v.ID}, v.Aliases...), " / ")
	}
	title := "Vulnerable dependency " + p.Name + "@" + p.Version
	if v.Summary != "" {
		title += ": " + v.Summary
	}
	fix := "Update " + p.Name + " to a fixed version."
	if v.Fixed != "" {
		fix = "Update " + p.Name + " to " + v.Fixed + " or later."
	}
	refs := []string{v.Ref}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			refs = append(refs, "https://nvd.nist.gov/vuln/detail/"+a)
		}
	}
	return core.Finding{
		Title:      title,
		Category:   core.CategoryCode,
		Severity:   sev,
		Confidence: conf,
		Asset:      core.Asset{Kind: core.AssetFile, Value: p.Name + "@" + p.Version, File: p.File, Criticality: t.Criticality},
		Location:   id,
		Evidence:   core.Evidence{Notes: p.Ecosystem + " package " + p.PURL + " — " + id},
		CWE:        []string{"CWE-1395"},
		OWASP:      []string{"A06:2021"},
		Remediation: core.Remediation{
			What:       "A third-party dependency (" + p.Name + ") has a known, published vulnerability (" + id + ").",
			Why:        "Published advisories are tracked by attackers; a vulnerable dependency is an exploit path into your app, independent of your own code.",
			How:        []core.Fix{{Stack: "generic", Language: "text", Code: fix + "\nThen re-run your package manager's audit (npm audit, pip-audit, govulncheck, cargo audit, composer audit …)."}},
			Effort:     core.EffortS,
			References: refs,
		},
	}
}

// severity maps the normalized label to Scout's scale. "Unknown" is treated as
// Medium/Likely — absence of a score is not safety.
func severity(label string) (core.Severity, core.Confidence) {
	switch label {
	case "Critical":
		return core.SeverityCritical, core.ConfidenceConfirmed
	case "High":
		return core.SeverityHigh, core.ConfidenceConfirmed
	case "Medium":
		return core.SeverityMedium, core.ConfidenceConfirmed
	case "Low":
		return core.SeverityLow, core.ConfidenceConfirmed
	default:
		return core.SeverityMedium, core.ConfidenceLikely
	}
}

// inventory walks the repo for known manifests and returns the deduped packages.
func inventory(root string) []intel.Package {
	var pkgs []intel.Package
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		parse, ok := parsers[d.Name()]
		if !ok {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxManifest {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 -- path from a walk of the user's own repo
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		pkgs = append(pkgs, parse(filepath.ToSlash(rel), data)...)
		return nil
	})
	return dedupe(pkgs)
}
