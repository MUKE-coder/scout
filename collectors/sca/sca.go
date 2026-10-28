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
	"fmt"
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

// enrich adds exploitation intelligence (CISA KEV + FIRST EPSS) to the matched
// vulns. A package var so tests can disable or fake it. nil skips enrichment.
var enrich enricherFunc = intel.NewEnricher().Enrich

type enricherFunc func(ctx context.Context, vulns []*intel.Vuln)

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

	// Enrich with exploitation intelligence (best-effort; leaves vulns unchanged
	// on failure). Done across all results at once so the feeds load just once.
	if enrich != nil {
		var flat []*intel.Vuln
		for i := range results {
			for j := range results[i] {
				flat = append(flat, &results[i][j])
			}
		}
		enrich(ctx, flat)
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
	// Observed in-the-wild exploitation (CISA KEV) makes a dependency urgent
	// regardless of its advisory severity: escalate to at least High.
	if v.KEV && sev < core.SeverityHigh {
		sev, conf = core.SeverityHigh, core.ConfidenceConfirmed
	}
	id := v.ID
	if len(v.Aliases) > 0 {
		id = strings.Join(append([]string{v.ID}, v.Aliases...), " / ")
	}
	title := "Vulnerable dependency " + p.Name + "@" + p.Version
	if v.KEV {
		title = "[Exploited] " + title
	}
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

	notes := p.Ecosystem + " package " + p.PURL + " — " + id
	if sig := exploitSignal(v); sig != "" {
		notes += " · " + sig
	}
	why := "Published advisories are tracked by attackers; a vulnerable dependency is an exploit path into your app, independent of your own code."
	if v.KEV {
		why = "This CVE is in CISA's Known Exploited Vulnerabilities catalog — it is being exploited in the wild right now"
		if v.Ransomware {
			why += ", including in ransomware campaigns"
		}
		why += ". Patch it ahead of advisories that are only theoretically exploitable."
		refs = append(refs, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
	}

	return core.Finding{
		Title:      title,
		Category:   core.CategoryCode,
		Severity:   sev,
		Confidence: conf,
		Asset:      core.Asset{Kind: core.AssetFile, Value: p.Name + "@" + p.Version, File: p.File, Criticality: t.Criticality},
		Location:   id,
		Evidence:   core.Evidence{Notes: notes},
		CWE:        []string{"CWE-1395"},
		OWASP:      []string{"A06:2021"},
		Remediation: core.Remediation{
			What:       "A third-party dependency (" + p.Name + ") has a known, published vulnerability (" + id + ").",
			Why:        why,
			How:        []core.Fix{{Stack: "generic", Language: "text", Code: fix + "\nThen re-run your package manager's audit (npm audit, pip-audit, govulncheck, cargo audit, composer audit …)."}},
			Effort:     core.EffortS,
			References: refs,
		},
	}
}

// exploitSignal renders the KEV/EPSS signals as a short, human line for a
// finding's evidence, e.g. "CISA KEV (ransomware) · EPSS 97% (p99)".
func exploitSignal(v intel.Vuln) string {
	var parts []string
	if v.KEV {
		s := "CISA KEV: exploited in the wild"
		if v.Ransomware {
			s = "CISA KEV: exploited in the wild (ransomware)"
		}
		parts = append(parts, s)
	}
	if v.EPSS > 0 {
		parts = append(parts, fmt.Sprintf("EPSS %.0f%% (p%.0f)", v.EPSS*100, v.EPSSPctl*100))
	}
	return strings.Join(parts, " · ")
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

// Inventory walks a repo for known dependency manifests/lockfiles across every
// supported ecosystem and returns the deduped packages. Exported so the SBOM
// generator can reuse the same inventory the vulnerable-deps check scans.
func Inventory(root string) []intel.Package { return inventory(repo.Base(root)) }

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
		data, err := os.ReadFile(path) // #nosec G304 G122 -- reading the user's own repo tree is the point; symlink TOCTOU is not a concern for a local read-only scan
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		pkgs = append(pkgs, parse(filepath.ToSlash(rel), data)...)
		return nil
	})
	return dedupe(pkgs)
}
