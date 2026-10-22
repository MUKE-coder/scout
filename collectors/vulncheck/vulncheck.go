// Package vulncheck finds known, reachable vulnerabilities in a Go module's
// dependencies by running govulncheck over the target's repository
// (Target.Repo). It is optional and degrades gracefully: if the repo is not a
// Go module, or govulncheck is not installed, or it cannot analyze the code,
// the check reports nothing rather than failing the scan.
//
// Note: govulncheck fetches the Go vulnerability database (vuln.go.dev by
// default) and must match the installed Go toolchain. For non-Go ecosystems,
// use a dedicated SCA tool; Scout does not bundle one.
package vulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MUKE-coder/scout/collectors/internal/repo"
	"github.com/MUKE-coder/scout/core"
)

func init() { core.Register(GoVulnCheck{}) }

// run executes govulncheck and returns its JSON stream. ok is false when the
// tool is absent or could not analyze the module (the caller then skips).
// It is a package var so tests can inject fixture output.
var run = defaultRun

func defaultRun(ctx context.Context, dir string) (out []byte, ok bool) {
	if _, err := exec.LookPath("govulncheck"); err != nil {
		return nil, false
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	// #nosec G204 -- fixed command and args; dir is the repo under scan
	cmd := exec.CommandContext(c, "govulncheck", "-json", "./...")
	cmd.Dir = dir
	data, err := cmd.Output()
	// govulncheck exits 0 (no vulns) or 3 (vulns found); other codes, or no
	// output, mean it could not analyze the module — skip rather than error.
	if len(data) == 0 {
		return nil, false
	}
	if err != nil {
		if ee, is := err.(*exec.ExitError); !is || ee.ExitCode() != 3 {
			// Keep going only if we still got finding output to parse.
		}
	}
	return data, true
}

// GoVulnCheck reports reachable CVEs in Go dependencies.
type GoVulnCheck struct{}

func (GoVulnCheck) ID() string              { return "code.go-vulncheck" }
func (GoVulnCheck) Category() core.Category { return core.CategoryCode }
func (GoVulnCheck) Mode() core.Mode         { return core.ModePassive }
func (GoVulnCheck) Description() string {
	return "A Go dependency has a known, reachable vulnerability"
}
func (GoVulnCheck) OWASP() []string { return []string{"A06:2021"} }
func (GoVulnCheck) ASVS() []string  { return []string{"V14.2.1"} }

func (GoVulnCheck) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	root := repo.Base(t.Repo)
	if root == "" {
		return nil, nil
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return nil, nil // not a Go module
	}
	data, ok := run(ctx, root)
	if !ok {
		return nil, nil
	}
	return parse(data, t), nil
}

// govulncheck -json emits a stream of objects, each with one of these keys.
type message struct {
	OSV     *osvEntry `json:"osv"`
	Finding *finding  `json:"finding"`
}

type osvEntry struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Database struct {
		URL string `json:"url"`
	} `json:"database_specific"`
}

type finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []frame `json:"trace"`
}

type frame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

// parse turns the govulncheck stream into findings: one per OSV id, marked
// reachable (called) when any finding's trace reaches a function.
func parse(data []byte, t core.Target) []core.Finding {
	osvs := map[string]osvEntry{}
	type agg struct {
		reachable bool
		fixed     string
		module    string
		version   string
	}
	found := map[string]*agg{}

	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var m message
		if err := dec.Decode(&m); err != nil {
			break
		}
		switch {
		case m.OSV != nil:
			osvs[m.OSV.ID] = *m.OSV
		case m.Finding != nil:
			a := found[m.Finding.OSV]
			if a == nil {
				a = &agg{}
				found[m.Finding.OSV] = a
			}
			if m.Finding.FixedVersion != "" {
				a.fixed = m.Finding.FixedVersion
			}
			if len(m.Finding.Trace) > 0 {
				top := m.Finding.Trace[0]
				if a.module == "" {
					a.module, a.version = top.Module, top.Version
				}
				if top.Function != "" {
					a.reachable = true
				}
			}
		}
	}

	ids := make([]string, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var out []core.Finding
	for _, id := range ids {
		a := found[id]
		osv := osvs[id]
		sev := core.SeverityMedium
		conf := core.ConfidenceLikely
		reach := "imported but not proven reachable"
		if a.reachable {
			sev, conf, reach = core.SeverityHigh, core.ConfidenceConfirmed, "a vulnerable function is called"
		}
		title := id
		if osv.Summary != "" {
			title = id + ": " + osv.Summary
		}
		refs := []string{"https://pkg.go.dev/vuln/" + id}
		if osv.Database.URL != "" {
			refs = []string{osv.Database.URL}
		}
		fix := "Update " + a.module + " to a fixed version."
		if a.fixed != "" {
			fix = "Update " + a.module + " to " + a.fixed + " or later."
		}
		out = append(out, core.Finding{
			Title:      "Vulnerable dependency " + title,
			Category:   core.CategoryCode,
			Severity:   sev,
			Confidence: conf,
			Asset:      core.Asset{Kind: core.AssetFile, Value: a.module + "@" + a.version, File: "go.mod", Criticality: t.Criticality},
			Location:   id,
			Evidence:   core.Evidence{Notes: a.module + "@" + a.version + " — " + reach},
			CWE:        []string{"CWE-1395"},
			OWASP:      []string{"A06:2021"},
			Remediation: core.Remediation{
				What:       "A dependency has a known vulnerability (" + id + ").",
				Why:        "Published CVEs are actively exploited; reachable ones are directly dangerous, and even unreachable ones become live as code changes.",
				How:        []core.Fix{{Stack: "generic", Language: "text", Code: fix + "\nRun `govulncheck ./...` locally and in CI."}},
				Effort:     core.EffortS,
				References: append(refs, aliasURLs(osv.Aliases)...),
			},
		})
	}
	return out
}

// aliasURLs turns CVE / GHSA aliases into reference links.
func aliasURLs(aliases []string) []string {
	var out []string
	for _, a := range aliases {
		switch {
		case strings.HasPrefix(a, "CVE-"):
			out = append(out, "https://nvd.nist.gov/vuln/detail/"+a)
		case strings.HasPrefix(a, "GHSA-"):
			out = append(out, "https://github.com/advisories/"+a)
		}
	}
	return out
}
