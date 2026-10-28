package cli

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/MUKE-coder/scout/intel"
)

func TestBuildSBOMComponents(t *testing.T) {
	pkgs := []intel.Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.11", PURL: "pkg:npm/lodash@4.17.11"},
		{Ecosystem: "Go", Name: "github.com/x/y", Version: "1.2.3"}, // no PURL → synthesized
	}
	doc := buildSBOM("/tmp/myapp", pkgs)
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" {
		t.Fatalf("header = %s %s", doc.BOMFormat, doc.SpecVersion)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("components = %d", len(doc.Components))
	}
	if doc.Components[1].PURL != "pkg:golang/github.com/x/y@1.2.3" {
		t.Errorf("synthesized purl = %q", doc.Components[1].PURL)
	}
	// Must serialize to valid JSON with the required CycloneDX keys.
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"bomFormat", "specVersion", "serialNumber", "metadata", "components"} {
		if _, ok := round[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
}

type fakeSBOMDB struct{}

func (fakeSBOMDB) Source() string { return "fake" }
func (fakeSBOMDB) Query(_ context.Context, pkgs []intel.Package) ([][]intel.Vuln, error) {
	out := make([][]intel.Vuln, len(pkgs))
	for i, p := range pkgs {
		if p.Name == "log4j-core" {
			out[i] = []intel.Vuln{{ID: "GHSA-x", Aliases: []string{"CVE-2021-44228"}, Summary: "RCE", Severity: "Critical", Fixed: "2.15.0"}}
		}
	}
	return out, nil
}

func TestAddVulnsEmbedsExploitIntel(t *testing.T) {
	origDB, origEn := sbomDB, sbomEnrich
	sbomDB = fakeSBOMDB{}
	sbomEnrich = func(_ context.Context, vulns []*intel.Vuln) {
		for _, v := range vulns {
			if v.CVEID() == "CVE-2021-44228" {
				v.CVE, v.KEV, v.Ransomware, v.EPSS, v.EPSSPctl = "CVE-2021-44228", true, true, 0.97, 0.99
			}
		}
	}
	defer func() { sbomDB, sbomEnrich = origDB, origEn }()

	pkgs := []intel.Package{{Ecosystem: "Maven", Name: "log4j-core", Version: "2.14.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}}
	doc := buildSBOM("app", pkgs)
	if err := addVulns(context.Background(), &doc, pkgs); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("vulns = %d", len(doc.Vulnerabilities))
	}
	v := doc.Vulnerabilities[0]
	if v.Ratings[0].Severity != "critical" {
		t.Errorf("severity = %q", v.Ratings[0].Severity)
	}
	if v.Affects[0].Ref != pkgs[0].PURL {
		t.Errorf("affects ref = %q", v.Affects[0].Ref)
	}
	props := map[string]string{}
	for _, p := range v.Properties {
		props[p.Name] = p.Value
	}
	if props["scout:cisa-kev"] != "true" || props["scout:kev-ransomware"] != "true" {
		t.Errorf("KEV properties missing: %v", props)
	}
	if props["scout:epss"] == "" {
		t.Errorf("EPSS property missing: %v", props)
	}
}
