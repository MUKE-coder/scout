package core

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Route is one entry of an app's route table, as exported by scout.Mount.
type Route struct {
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	Handler    string   `json:"handler,omitempty"`
	Middleware []string `json:"middleware,omitempty"`
}

// Identity is a disposable test account the access-control checks use to probe
// authorization boundaries. It is never a real user. Headers carry whatever
// authenticates it (e.g. "Authorization: Bearer ...", "Cookie: session=..."),
// which the checks attach to requests they make as this identity. Owns lists
// private resources (absolute URLs, or paths resolved against the target URL)
// that this identity legitimately owns; the IDOR check asks whether a
// *different* identity can read them. Every probe using these is read-only.
type Identity struct {
	Name    string            `json:"name" yaml:"name"`
	Headers map[string]string `json:"headers,omitempty" yaml:"headers"`
	Owns    []string          `json:"owns,omitempty" yaml:"owns"`
}

// Target is something Scout scans: a URL, a host, a repo, or all three.
type Target struct {
	Name string `json:"name" yaml:"name"`
	// URL is the base URL for black-box scanning ("https://example.com").
	URL string `json:"url,omitempty" yaml:"url"`
	// Repo is a local path for code and supply-chain collectors.
	Repo string `json:"repo,omitempty" yaml:"repo"`

	Environment Environment `json:"environment" yaml:"environment"`
	// AllowActive is the explicit per-target opt-in required for Active
	// mode in prod and Intrusive mode in staging.
	AllowActive bool `json:"allow_active,omitempty" yaml:"allow_active"`
	// Criticality is the default asset criticality for findings on this target.
	Criticality float64 `json:"criticality,omitempty" yaml:"criticality"`

	// Routes is the real route table when the app uses scout.Mount.
	Routes []Route `json:"routes,omitempty" yaml:"-"`

	// Identities are disposable test accounts for access-control checks
	// (e.g. IDOR). Never real users. Set via scout.WithTestIdentities or the
	// config file; empty disables the identity-dependent checks for this
	// target. Not serialized in scan results (may carry credentials).
	Identities []Identity `json:"-" yaml:"identities"`
}

// Host returns the hostname of the target URL, or "" if there is none.
func (t Target) Host() string {
	if t.URL == "" {
		return ""
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// IsLocal reports whether the target is loopback or a private address, where
// ownership verification is not required.
func (t Target) IsLocal() bool {
	h := t.Host()
	if h == "" {
		return t.Repo != ""
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// Validate checks that the target names something scannable.
func (t Target) Validate() error {
	if t.URL == "" && t.Repo == "" {
		return fmt.Errorf("target %q: needs a URL or a repo", t.Name)
	}
	if t.URL != "" {
		u, err := url.Parse(t.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("target %q: %q is not an http(s) URL", t.Name, t.URL)
		}
	}
	if _, err := ParseEnvironment(string(t.Environment)); err != nil {
		return fmt.Errorf("target %q: %w", t.Name, err)
	}
	return nil
}

// SkippedCheck records a check the engine chose not to run, and why.
type SkippedCheck struct {
	CheckID string `json:"check_id"`
	Mode    Mode   `json:"mode"`
	Reason  string `json:"reason"`
}

// CheckError records a check that failed or panicked.
type CheckError struct {
	CheckID string `json:"check_id"`
	Error   string `json:"error"`
}

// ScanResult is the outcome of one scan.
type ScanResult struct {
	ID         string         `json:"id"`
	Target     Target         `json:"target"`
	Mode       Mode           `json:"mode"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Findings   []Finding      `json:"findings"`
	Skipped    []SkippedCheck `json:"skipped,omitempty"`
	Errors     []CheckError   `json:"errors,omitempty"`
	Score      float64        `json:"score"`
	Grade      string         `json:"grade"`
	// Assessed lists the categories of the checks that ran; the score only
	// covers these.
	Assessed []Category `json:"assessed,omitempty"`
}
