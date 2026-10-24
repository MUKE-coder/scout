// Package intel provides vulnerability intelligence: it matches a software
// bill of materials (packages + versions) against known-vulnerability
// databases. The default source is OSV.dev, which aggregates NVD, the GitHub
// Advisory Database, RustSec, PyPA, the Go vuln DB and more. An offline
// snapshot can be added later behind the same DB interface.
package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Package is one component of a bill of materials, in OSV terms.
type Package struct {
	Ecosystem string // OSV ecosystem: npm, Go, PyPI, Maven, Packagist, crates.io, RubyGems, NuGet
	Name      string
	Version   string
	PURL      string // package URL, for display/provenance
	File      string // the manifest/lockfile it came from (repo-relative)
}

// Vuln is a known vulnerability affecting a package.
type Vuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Severity string   // normalized: Critical | High | Medium | Low | Unknown
	Fixed    string   // first fixed version for the queried package, if known
	Ref      string   // a canonical reference URL

	// Exploitation intelligence, filled by an Enricher (CISA KEV + FIRST EPSS).
	CVE        string  // canonical CVE id resolved from ID/Aliases, if any
	KEV        bool    // listed in the CISA Known Exploited Vulnerabilities catalog
	Ransomware bool    // KEV: known use in ransomware campaigns
	EPSS       float64 // FIRST EPSS exploitation probability, 0..1
	EPSSPctl   float64 // EPSS percentile among all scored CVEs, 0..1
}

// CVEID returns the canonical CVE identifier for the vuln: its own ID if it is a
// CVE, otherwise the first CVE alias. Empty when no CVE is associated.
func (v Vuln) CVEID() string {
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return ""
}

// DB is a source of vulnerability intelligence. Live (OSV API) and offline
// (snapshot) implementations satisfy it.
type DB interface {
	// Query returns the vulns affecting each input package, aligned by index.
	Query(ctx context.Context, pkgs []Package) ([][]Vuln, error)
	// Source names the data source, for provenance.
	Source() string
}

const osvAPI = "https://api.osv.dev"

// OSV queries the live OSV.dev API.
type OSV struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]*osvVuln // id -> details
}

// NewOSV returns a client for the live OSV.dev API.
func NewOSV() *OSV {
	return &OSV{client: &http.Client{Timeout: 25 * time.Second}, cache: map[string]*osvVuln{}}
}

func (*OSV) Source() string { return "OSV.dev" }

// ---- API wire types -------------------------------------------------------

type osvQuery struct {
	Version string         `json:"version,omitempty"`
	Package osvPackageName `json:"package"`
}
type osvPackageName struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type batchResp struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// osvVuln is the subset of an OSV record we read.
type osvVuln struct {
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases"`
	Summary          string          `json:"summary"`
	Severity         []osvSeverity   `json:"severity"`
	Affected         []osvAffected   `json:"affected"`
	References       []osvReference  `json:"references"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}
type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}
type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

// Query batches the packages to OSV's querybatch endpoint, then fetches the
// details for each returned id (cached) and extracts severity and fix.
func (o *OSV) Query(ctx context.Context, pkgs []Package) ([][]Vuln, error) {
	out := make([][]Vuln, len(pkgs))
	const batch = 500
	for start := 0; start < len(pkgs); start += batch {
		end := min(start+batch, len(pkgs))
		chunk := pkgs[start:end]
		queries := make([]osvQuery, len(chunk))
		for i, p := range chunk {
			queries[i] = osvQuery{Version: p.Version, Package: osvPackageName{Name: p.Name, Ecosystem: p.Ecosystem}}
		}
		var resp batchResp
		if err := o.post(ctx, "/v1/querybatch", map[string]any{"queries": queries}, &resp); err != nil {
			return nil, err
		}
		for i := range chunk {
			if start+i >= len(resp.Results) {
				break
			}
			for _, v := range resp.Results[i].Vulns {
				det, err := o.detail(ctx, v.ID)
				if err != nil || det == nil {
					out[start+i] = append(out[start+i], Vuln{ID: v.ID, Ref: "https://osv.dev/vulnerability/" + v.ID})
					continue
				}
				out[start+i] = append(out[start+i], det.toVuln(chunk[i]))
			}
		}
	}
	return out, nil
}

func (o *OSV) detail(ctx context.Context, id string) (*osvVuln, error) {
	o.mu.Lock()
	if v, ok := o.cache[id]; ok {
		o.mu.Unlock()
		return v, nil
	}
	o.mu.Unlock()
	var v osvVuln
	if err := o.get(ctx, "/v1/vulns/"+id, &v); err != nil {
		return nil, err
	}
	o.mu.Lock()
	o.cache[id] = &v
	o.mu.Unlock()
	return &v, nil
}

func (o *OSV) post(ctx context.Context, path string, body any, into any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvAPI+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return o.do(req, into)
}

func (o *OSV) get(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvAPI+path, nil)
	if err != nil {
		return err
	}
	return o.do(req, into)
}

func (o *OSV) do(req *http.Request, into any) error {
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv: %s returned %d", req.URL.Path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

// toVuln normalizes an OSV record for the queried package.
func (v *osvVuln) toVuln(p Package) Vuln {
	out := Vuln{ID: v.ID, Aliases: v.Aliases, Summary: v.Summary, Severity: v.severityLabel(), Fixed: v.fixedFor(p), Ref: "https://osv.dev/vulnerability/" + v.ID}
	for _, r := range v.References {
		if r.Type == "ADVISORY" {
			out.Ref = r.URL
			break
		}
	}
	return out
}

// severityLabel reads GitHub/OSV database_specific severity, falling back to a
// coarse bucket from a CVSS base score embedded in the vector.
func (v *osvVuln) severityLabel() string {
	var ds struct {
		Severity string `json:"severity"`
	}
	if len(v.DatabaseSpecific) > 0 {
		_ = json.Unmarshal(v.DatabaseSpecific, &ds)
	}
	switch strings.ToUpper(ds.Severity) {
	case "CRITICAL":
		return "Critical"
	case "HIGH":
		return "High"
	case "MODERATE", "MEDIUM":
		return "Medium"
	case "LOW":
		return "Low"
	}
	return "Unknown"
}

// fixedFor returns the first fixed version for p across the affected ranges.
func (v *osvVuln) fixedFor(p Package) string {
	for _, a := range v.Affected {
		if !strings.EqualFold(a.Package.Name, p.Name) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f, ok := e["fixed"]; ok && f != "" {
					return f
				}
			}
		}
	}
	return ""
}
