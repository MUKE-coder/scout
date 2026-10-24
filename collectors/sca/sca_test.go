package sca

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/intel"
)

type fakeDB struct{}

func (fakeDB) Source() string { return "fake" }
func (fakeDB) Query(_ context.Context, pkgs []intel.Package) ([][]intel.Vuln, error) {
	out := make([][]intel.Vuln, len(pkgs))
	for i, p := range pkgs {
		if p.Name == "lodash" {
			out[i] = []intel.Vuln{{
				ID: "GHSA-xxxx", Aliases: []string{"CVE-2021-23337"},
				Summary: "Command injection in lodash", Severity: "High", Fixed: "4.17.21",
				Ref: "https://osv.dev/vulnerability/GHSA-xxxx",
			}}
		}
	}
	return out, nil
}

func TestSCARun(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"),
		[]byte(`{"packages":{"":{},"node_modules/lodash":{"version":"4.17.11"},"node_modules/safe":{"version":"1.0.0"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := db
	db = fakeDB{}
	origEnrich := enrich
	enrich = nil // no network enrichment in this test
	defer func() { db = orig; enrich = origEnrich }()

	got, err := Deps{}.Run(context.Background(), core.Target{Repo: dir, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Severity != core.SeverityHigh {
		t.Errorf("severity = %v", f.Severity)
	}
	if f.Asset.Value != "lodash@4.17.11" {
		t.Errorf("asset = %q", f.Asset.Value)
	}
	if f.Asset.File != "package-lock.json" {
		t.Errorf("file = %q", f.Asset.File)
	}
	if !strings.Contains(f.Remediation.How[0].Code, "4.17.21") {
		t.Errorf("remediation missing fixed version: %q", f.Remediation.How[0].Code)
	}
}

// A low-severity dependency that is in CISA KEV must escalate to High, get the
// [Exploited] marker, and carry the exploitation signal in its evidence.
func TestKEVEscalation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"),
		[]byte(`{"packages":{"":{},"node_modules/lodash":{"version":"4.17.11"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := db
	db = lowSevDB{}
	origEnrich := enrich
	enrich = func(_ context.Context, vulns []*intel.Vuln) {
		for _, v := range vulns {
			if v.CVEID() == "CVE-2021-23337" {
				v.CVE, v.KEV, v.Ransomware, v.EPSS, v.EPSSPctl = "CVE-2021-23337", true, true, 0.97, 0.99
			}
		}
	}
	defer func() { db = orig; enrich = origEnrich }()

	got, err := Deps{}.Run(context.Background(), core.Target{Repo: dir, Environment: core.EnvDev})
	if err != nil || len(got) != 1 {
		t.Fatalf("want 1 finding: %d %v", len(got), err)
	}
	f := got[0]
	if f.Severity != core.SeverityHigh {
		t.Errorf("KEV should escalate Low -> High, got %v", f.Severity)
	}
	if !strings.HasPrefix(f.Title, "[Exploited] ") {
		t.Errorf("title missing [Exploited] marker: %q", f.Title)
	}
	if !strings.Contains(f.Evidence.Notes, "CISA KEV") || !strings.Contains(f.Evidence.Notes, "EPSS 97%") {
		t.Errorf("evidence missing exploitation signal: %q", f.Evidence.Notes)
	}
	if !strings.Contains(f.Remediation.Why, "exploited in the wild") {
		t.Errorf("remediation why not updated for KEV: %q", f.Remediation.Why)
	}
}

type lowSevDB struct{}

func (lowSevDB) Source() string { return "low" }
func (lowSevDB) Query(_ context.Context, pkgs []intel.Package) ([][]intel.Vuln, error) {
	out := make([][]intel.Vuln, len(pkgs))
	for i, p := range pkgs {
		if p.Name == "lodash" {
			out[i] = []intel.Vuln{{ID: "GHSA-low", Aliases: []string{"CVE-2021-23337"}, Summary: "x", Severity: "Low"}}
		}
	}
	return out, nil
}

func TestSCANoRepo(t *testing.T) {
	got, err := Deps{}.Run(context.Background(), core.Target{URL: "https://x", Environment: core.EnvDev})
	if err != nil || got != nil {
		t.Fatalf("url-only should be a no-op: %v %v", got, err)
	}
}
