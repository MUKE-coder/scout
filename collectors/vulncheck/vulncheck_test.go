package vulncheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

// Sample govulncheck -json output: two OSV entries, one reachable (a vulnerable
// function is called) and one imported-only (no function in the trace).
const sampleJSON = `
{"osv":{"id":"GO-2024-0001","summary":"stdlib: denial of service","aliases":["CVE-2024-1111","GHSA-aaaa-bbbb-cccc"],"database_specific":{"url":"https://pkg.go.dev/vuln/GO-2024-0001"}}}
{"osv":{"id":"GO-2024-0002","summary":"example: info leak","aliases":["CVE-2024-2222"]}}
{"finding":{"osv":"GO-2024-0001","fixed_version":"v1.2.3","trace":[{"module":"example.com/vuln","version":"v1.0.0","package":"example.com/vuln/pkg","function":"Exploitable"}]}}
{"finding":{"osv":"GO-2024-0002","fixed_version":"v2.0.0","trace":[{"module":"example.com/other","version":"v0.1.0","package":"example.com/other/pkg"}]}}
`

func findingByLocation(fs []core.Finding, id string) *core.Finding {
	for i := range fs {
		if fs[i].Location == id {
			return &fs[i]
		}
	}
	return nil
}

func TestParseReachableVsImported(t *testing.T) {
	out := parse([]byte(sampleJSON), core.Target{Environment: core.EnvDev})
	if len(out) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(out), out)
	}

	reach := findingByLocation(out, "GO-2024-0001")
	if reach == nil {
		t.Fatal("missing GO-2024-0001")
	}
	if reach.Severity != core.SeverityHigh || reach.Confidence != core.ConfidenceConfirmed {
		t.Errorf("reachable: sev=%v conf=%v", reach.Severity, reach.Confidence)
	}
	if reach.Asset.Value != "example.com/vuln@v1.0.0" {
		t.Errorf("reachable asset = %q", reach.Asset.Value)
	}
	refs := reach.Remediation.References
	if !contains(refs, "https://nvd.nist.gov/vuln/detail/CVE-2024-1111") ||
		!contains(refs, "https://github.com/advisories/GHSA-aaaa-bbbb-cccc") {
		t.Errorf("reachable refs missing alias URLs: %v", refs)
	}

	imp := findingByLocation(out, "GO-2024-0002")
	if imp == nil {
		t.Fatal("missing GO-2024-0002")
	}
	if imp.Severity != core.SeverityMedium || imp.Confidence != core.ConfidenceLikely {
		t.Errorf("imported-only: sev=%v conf=%v", imp.Severity, imp.Confidence)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestRunNoGoModule(t *testing.T) {
	// No go.mod in the temp dir: Run must report nothing.
	dir := t.TempDir()
	got, err := GoVulnCheck{}.Run(context.Background(), core.Target{Repo: dir, Environment: core.EnvDev})
	if err != nil || got != nil {
		t.Fatalf("no go.mod: got=%v err=%v", got, err)
	}
}

func TestRunWithInjectedRunner(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := run
	run = func(context.Context, string) ([]byte, bool) { return []byte(sampleJSON), true }
	defer func() { run = orig }()

	got, err := GoVulnCheck{}.Run(context.Background(), core.Target{Repo: dir, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 findings from injected runner, got %d", len(got))
	}
}

func TestRunNoRepo(t *testing.T) {
	got, err := GoVulnCheck{}.Run(context.Background(), core.Target{URL: "https://x", Environment: core.EnvDev})
	if err != nil || got != nil {
		t.Fatalf("url-only: got=%v err=%v", got, err)
	}
}
