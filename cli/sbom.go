package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	scout "github.com/MUKE-coder/scout"
	"github.com/MUKE-coder/scout/collectors/sca"
	"github.com/MUKE-coder/scout/intel"
)

// Injectable for tests.
var (
	sbomDB     intel.DB = intel.NewOSV()
	sbomEnrich          = intel.NewEnricher().Enrich
)

// --- CycloneDX 1.6 (the subset Scout emits) --------------------------------

type cdxDoc struct {
	BOMFormat       string    `json:"bomFormat"`
	SpecVersion     string    `json:"specVersion"`
	SerialNumber    string    `json:"serialNumber"`
	Version         int       `json:"version"`
	Metadata        cdxMeta   `json:"metadata"`
	Components      []cdxComp `json:"components"`
	Vulnerabilities []cdxVuln `json:"vulnerabilities,omitempty"`
}

type cdxMeta struct {
	Timestamp string   `json:"timestamp"`
	Tools     cdxTools `json:"tools"`
	Component cdxComp  `json:"component"`
}

type cdxTools struct {
	Components []cdxComp `json:"components"`
}

type cdxComp struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Group   string `json:"group,omitempty"`
}

type cdxVuln struct {
	BOMRef      string        `json:"bom-ref,omitempty"`
	ID          string        `json:"id"`
	Source      cdxSource     `json:"source"`
	Ratings     []cdxRating   `json:"ratings,omitempty"`
	Advisories  []cdxAdvisory `json:"advisories,omitempty"`
	Description string        `json:"description,omitempty"`
	Recommend   string        `json:"recommendation,omitempty"`
	Affects     []cdxAffect   `json:"affects"`
	Properties  []cdxProperty `json:"properties,omitempty"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}
type cdxRating struct {
	Source   cdxSource `json:"source,omitempty"`
	Severity string    `json:"severity"`
	Method   string    `json:"method,omitempty"`
}
type cdxAdvisory struct {
	URL string `json:"url"`
}
type cdxAffect struct {
	Ref string `json:"ref"`
}
type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func newSBOMCmd() *cobra.Command {
	var (
		repoPath string
		out      string
		noVulns  bool
	)
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Generate a CycloneDX SBOM of a repo's dependencies (with vulnerabilities)",
		Long: "Inventory a repository's dependencies across every supported ecosystem and emit a " +
			"CycloneDX 1.6 SBOM. Unlike a plain SBOM, Scout embeds the known vulnerabilities for each " +
			"component — enriched with CISA KEV and FIRST EPSS — so the bill of materials carries its own " +
			"exploitation triage. Pass --no-vulns for a components-only SBOM (no network).",
		Example: "  scout sbom --repo .\n  scout sbom --repo . -o sbom.cdx.json\n  scout sbom --repo . --no-vulns",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pkgs := sca.Inventory(repoPath)
			if len(pkgs) == 0 {
				return fmt.Errorf("no dependencies found under %q (looked for lockfiles/manifests)", repoPath)
			}

			doc := buildSBOM(repoPath, pkgs)
			if !noVulns {
				if err := addVulns(cmd.Context(), &doc, pkgs); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "note: vulnerability data unavailable (%v); emitting components only\n", err)
				}
			}

			b, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				return err
			}
			b = append(b, '\n')
			if out == "" {
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			if err := os.WriteFile(out, b, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Wrote %d components (%d with vulnerabilities) to %s\n",
				len(doc.Components), len(doc.Vulnerabilities), out)
			return nil
		},
	}
	cmd.Flags().StringVar(&repoPath, "repo", ".", "repository path to inventory")
	cmd.Flags().StringVarP(&out, "output", "o", "", "write the SBOM to this file instead of stdout")
	cmd.Flags().BoolVar(&noVulns, "no-vulns", false, "components only; do not query vulnerability data")
	return cmd
}

func buildSBOM(repoPath string, pkgs []intel.Package) cdxDoc {
	name := filepath.Base(absOrSelf(repoPath))
	if name == "." || name == "" || name == string(filepath.Separator) {
		name = "application"
	}
	return cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + uuidV4(),
		Version:      1,
		Metadata: cdxMeta{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: cdxTools{Components: []cdxComp{
				{Type: "application", Name: "scout", Group: "scout", Version: scout.Version},
			}},
			Component: cdxComp{Type: "application", BOMRef: "root", Name: name},
		},
		Components: components(pkgs),
	}
}

func components(pkgs []intel.Package) []cdxComp {
	out := make([]cdxComp, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, cdxComp{
			Type:    "library",
			BOMRef:  bomRef(p),
			Name:    p.Name,
			Version: p.Version,
			PURL:    purlOf(p),
		})
	}
	return out
}

// addVulns queries the vulnerability DB for the inventory, enriches it with KEV
// and EPSS, and attaches a CycloneDX vulnerability per advisory.
func addVulns(ctx context.Context, doc *cdxDoc, pkgs []intel.Package) error {
	results, err := sbomDB.Query(ctx, pkgs)
	if err != nil {
		return err
	}
	if sbomEnrich != nil {
		var flat []*intel.Vuln
		for i := range results {
			for j := range results[i] {
				flat = append(flat, &results[i][j])
			}
		}
		sbomEnrich(ctx, flat)
	}
	seen := map[string]bool{}
	for i, vulns := range results {
		if i >= len(pkgs) {
			break
		}
		ref := bomRef(pkgs[i])
		for _, v := range vulns {
			key := ref + "|" + v.ID
			if seen[key] {
				continue
			}
			seen[key] = true
			doc.Vulnerabilities = append(doc.Vulnerabilities, vulnEntry(ref, pkgs[i], v))
		}
	}
	return nil
}

func vulnEntry(ref string, p intel.Package, v intel.Vuln) cdxVuln {
	cv := cdxVuln{
		BOMRef:      ref + "/" + v.ID,
		ID:          v.ID,
		Source:      cdxSource{Name: "OSV", URL: "https://osv.dev/vulnerability/" + v.ID},
		Ratings:     []cdxRating{{Source: cdxSource{Name: "OSV"}, Severity: cdxSeverity(v.Severity)}},
		Description: v.Summary,
		Affects:     []cdxAffect{{Ref: ref}},
	}
	if v.Ref != "" {
		cv.Advisories = []cdxAdvisory{{URL: v.Ref}}
	}
	if v.Fixed != "" {
		cv.Recommend = "Update " + p.Name + " to " + v.Fixed + " or later."
	}
	// Scout's exploitation intelligence, as CycloneDX properties.
	if v.CVE != "" {
		cv.Properties = append(cv.Properties, cdxProperty{Name: "scout:cve", Value: v.CVE})
	}
	if v.KEV {
		cv.Properties = append(cv.Properties, cdxProperty{Name: "scout:cisa-kev", Value: "true"})
		if v.Ransomware {
			cv.Properties = append(cv.Properties, cdxProperty{Name: "scout:kev-ransomware", Value: "true"})
		}
	}
	if v.EPSS > 0 {
		cv.Properties = append(cv.Properties,
			cdxProperty{Name: "scout:epss", Value: fmt.Sprintf("%.5f", v.EPSS)},
			cdxProperty{Name: "scout:epss-percentile", Value: fmt.Sprintf("%.5f", v.EPSSPctl)},
		)
	}
	return cv
}

// cdxSeverity maps Scout's label to the CycloneDX rating vocabulary.
func cdxSeverity(label string) string {
	switch label {
	case "Critical":
		return "critical"
	case "High":
		return "high"
	case "Medium":
		return "medium"
	case "Low":
		return "low"
	default:
		return "unknown"
	}
}

func bomRef(p intel.Package) string {
	if r := purlOf(p); r != "" {
		return r
	}
	return p.Ecosystem + ":" + p.Name + "@" + p.Version
}

// purlOf returns the package's purl, synthesizing one from the ecosystem when a
// parser did not supply it.
func purlOf(p intel.Package) string {
	if p.PURL != "" {
		return p.PURL
	}
	t := purlType(p.Ecosystem)
	if t == "" || p.Name == "" {
		return ""
	}
	return "pkg:" + t + "/" + p.Name + "@" + p.Version
}

// purlType maps an OSV ecosystem to a Package-URL type.
func purlType(eco string) string {
	switch strings.ToLower(eco) {
	case "npm":
		return "npm"
	case "go":
		return "golang"
	case "pypi":
		return "pypi"
	case "maven":
		return "maven"
	case "packagist":
		return "composer"
	case "rubygems":
		return "gem"
	case "crates.io":
		return "cargo"
	case "nuget":
		return "nuget"
	case "pub":
		return "pub"
	case "hex":
		return "hex"
	default:
		return ""
	}
}

func absOrSelf(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// uuidV4 returns a random RFC 4122 version-4 UUID.
func uuidV4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
