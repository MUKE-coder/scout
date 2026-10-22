package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func TestJSONDocument(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, "1.2.3", []Result{build()}); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Tool != "scout" || doc.Version != "1.2.3" || len(doc.Results) != 1 {
		t.Fatalf("doc = %+v", doc)
	}
	r := doc.Results[0]
	if r.Report.Grade != "F" || len(r.Scan.Findings) != 3 || len(r.FixNext) != 3 {
		t.Fatalf("result lost data: grade %s, %d findings, %d fix-next", r.Report.Grade, len(r.Scan.Findings), len(r.FixNext))
	}
	if r.Scan.Findings[0].Severity.String() == "" {
		t.Fatal("enums should round-trip as text")
	}
}

func TestJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	_ = JSON(&buf, "x", nil)
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	if res, ok := doc["results"].([]any); !ok || len(res) != 0 {
		t.Fatalf("results should be an empty array, got %v", doc["results"])
	}
}

func TestSARIF(t *testing.T) {
	r := build()
	// Add a closed finding (excluded) and a file finding (gets a line region).
	closed := r.Scan.Findings[0]
	closed.Fingerprint, closed.Status = "closed-one", core.StatusFixed
	file := core.Finding{CheckID: "code.secret", Title: "Hard-coded key", Category: core.CategoryCode,
		Severity: core.SeverityHigh, Confidence: core.ConfidenceConfirmed,
		Asset: core.Asset{Kind: core.AssetFile, Value: "config/app.go:12", File: "config/app.go", Line: 12}}
	file.Normalize()
	r.Scan.Findings = append(r.Scan.Findings, closed, file)

	var buf bytes.Buffer
	if err := SARIF(&buf, "1.2.3", []Result{r}); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("log = %+v", log)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "Scout" || run.Tool.Driver.Version != "1.2.3" {
		t.Fatalf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Results) != 4 {
		t.Fatalf("results = %d, want 4 open findings", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 4 {
		t.Fatalf("rules = %d, want one per check", len(run.Tool.Driver.Rules))
	}

	byRule := map[string]sarifResult{}
	for _, res := range run.Results {
		byRule[res.RuleID] = res
		if res.PartialFingerprints["scoutFingerprint/v1"] == "" {
			t.Errorf("%s: missing partial fingerprint", res.RuleID)
		}
	}
	if byRule["app.injection"].Level != "error" || byRule["headers.csp"].Level != "warning" || byRule["headers.nosniff"].Level != "note" {
		t.Errorf("levels wrong: %+v", byRule)
	}
	loc := byRule["code.secret"].Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "config/app.go" || loc.Region == nil || loc.Region.StartLine != 12 {
		t.Errorf("file location = %+v", loc)
	}
	for _, rule := range run.Tool.Driver.Rules {
		if rule.ID == "app.injection" && rule.Properties["security-severity"] != "9.5" {
			t.Errorf("critical security-severity = %v", rule.Properties["security-severity"])
		}
	}
}
