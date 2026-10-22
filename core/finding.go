package core

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// AssetKind says what kind of thing an Asset is.
type AssetKind string

const (
	AssetDomain    AssetKind = "domain"
	AssetHost      AssetKind = "host"      // host:port
	AssetURL       AssetKind = "url"       // a page or endpoint
	AssetRoute     AssetKind = "route"     // METHOD /path from a route table
	AssetFile      AssetKind = "file"      // file:line in a repo
	AssetContainer AssetKind = "container" // container or image
)

// Asset is the thing a finding is about.
type Asset struct {
	Kind  AssetKind `json:"kind"`
	Value string    `json:"value"` // canonical display form: "example.com", "10.0.0.1:6379", "GET /api/users/:id", "main.go:42"

	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`

	Exposure Exposure `json:"exposure,omitempty"`
	// Criticality scales risk for this asset (payments API 1.5, marketing
	// site 0.7). Zero means the default of 1.0.
	Criticality float64 `json:"criticality,omitempty"`
}

// Key is a stable identity for the asset, independent of display metadata.
func (a Asset) Key() string {
	parts := []string{string(a.Kind), a.Value, a.Host, strconv.Itoa(a.Port),
		strings.ToUpper(a.Method), a.Path, a.File, strconv.Itoa(a.Line)}
	return strings.Join(parts, "|")
}

// Evidence is what Scout saw that made it raise a finding.
type Evidence struct {
	Request    string `json:"request,omitempty"`     // raw HTTP request
	Response   string `json:"response,omitempty"`    // raw HTTP response (possibly truncated)
	Matched    string `json:"matched,omitempty"`     // the payload or pattern that matched
	ConfigLine string `json:"config_line,omitempty"` // offending config or source line
	Notes      string `json:"notes,omitempty"`
	Redacted   bool   `json:"redacted,omitempty"`
}

// Fix is one stack-specific way to remediate a finding.
type Fix struct {
	Stack    string `json:"stack"`    // "gin", "nginx", "caddy", "nextjs", "dockerfile", "sentinel", "generic"
	Language string `json:"language"` // syntax hint for the code viewer: "go", "nginx", "yaml"...
	Code     string `json:"code"`
	Note     string `json:"note,omitempty"`
}

// Remediation is the deterministic fix guidance attached to a finding.
type Remediation struct {
	What       string   `json:"what"`          // plain-language description
	Why        string   `json:"why"`           // realistic attack scenario
	How        []Fix    `json:"how,omitempty"` // stack-specific fixes
	Effort     Effort   `json:"effort"`        // S | M | L
	References []string `json:"references,omitempty"`
}

// Finding is the single shape every collector emits. It is what makes
// dedupe, diffs, scoring and the dashboard possible.
type Finding struct {
	Fingerprint string     `json:"fingerprint"`
	CheckID     string     `json:"check_id"`
	Title       string     `json:"title"`
	Category    Category   `json:"category"`
	Severity    Severity   `json:"severity"`
	CVSS        float64    `json:"cvss,omitempty"`
	Confidence  Confidence `json:"confidence"`
	Asset       Asset      `json:"asset"`
	// Location distinguishes several findings from one check on one asset,
	// such as a cookie name or a form parameter.
	Location    string      `json:"location,omitempty"`
	Evidence    Evidence    `json:"evidence"`
	CWE         []string    `json:"cwe,omitempty"`
	OWASP       []string    `json:"owasp,omitempty"`
	Remediation Remediation `json:"remediation"`
	// Tags mark findings that scoring treats specially, such as TagExpiredCert.
	Tags      []string  `json:"tags,omitempty"`
	Status    Status    `json:"status"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Finding tags with scoring meaning.
const (
	// TagExpiredCert marks an expired TLS certificate (caps the grade at D).
	TagExpiredCert = "expired-cert"
	// TagExposedSecret marks a leaked credential or key (caps the grade at D
	// when the asset is internet-facing).
	TagExposedSecret = "exposed-secret"
)

// HasTag reports whether the finding carries tag.
func (f Finding) HasTag(tag string) bool {
	for _, t := range f.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// Fingerprint returns the stable identity of a finding: checkID + asset +
// location. It deliberately ignores evidence, severity and timestamps so the
// same issue keeps the same fingerprint across scans.
func Fingerprint(checkID string, asset Asset, location string) string {
	h := sha256.New()
	h.Write([]byte(checkID))
	h.Write([]byte{0})
	h.Write([]byte(asset.Key()))
	h.Write([]byte{0})
	h.Write([]byte(location))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Normalize fills derived fields: the fingerprint and a default status.
func (f *Finding) Normalize() {
	f.Fingerprint = Fingerprint(f.CheckID, f.Asset, f.Location)
	if f.Status == "" {
		f.Status = StatusOpen
	}
}
