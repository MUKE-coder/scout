// Package ai adds optional AI explanations through the Vercel AI Gateway's
// OpenAI-compatible API. It is off unless configured. Findings are redacted
// before anything leaves the process: evidence bodies and payloads are never
// sent, and hosts, emails, IPs, query strings and token-like values are
// masked in the text that is.
package ai

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/MUKE-coder/scout/core"
)

// RedactedFinding is everything about a finding that may be sent to a model.
type RedactedFinding struct {
	CheckID    string   `json:"check_id"`
	Title      string   `json:"title"`
	Category   string   `json:"category"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	AssetKind  string   `json:"asset_kind"`
	Asset      string   `json:"asset"` // host masked, query dropped
	CWE        []string `json:"cwe,omitempty"`
	OWASP      []string `json:"owasp,omitempty"`
	What       string   `json:"what,omitempty"`
	Why        string   `json:"why,omitempty"`
	FixStacks  []string `json:"fix_stacks,omitempty"`
	Effort     string   `json:"effort,omitempty"`
}

var (
	reEmail = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	reIPv4  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// Full or "::"-compressed IPv6 (the compressed form needs the "::").
	reIPv6   = regexp.MustCompile(`(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?|::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})`)
	reJWT    = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*`)
	reBearer = regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=\-]{8,}`)
	reKV     = regexp.MustCompile(`(?i)\b(pass(word)?|pwd|secret|token|api[_-]?key|access[_-]?key|auth|session|cookie|key)\s*[=:]\s*["']?[^\s"'&;,]+`)
	reLong   = regexp.MustCompile(`\b[A-Za-z0-9_\-+/]{32,}={0,2}\b`)
	reURL    = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s"'<>]+`)
)

// Text masks sensitive values in free text. host, when non-empty, is
// replaced everywhere it appears.
func Text(s, host string) string {
	if s == "" {
		return s
	}
	// Order matters: URLs first (dropping credentials and queries, which
	// look like emails), then emails before the host is masked (or
	// "admin@<host>" would leak the mailbox), IPv6 before IPv4.
	s = reURL.ReplaceAllStringFunc(s, maskURL)
	s = reEmail.ReplaceAllString(s, "<email>")
	if host != "" {
		s = strings.ReplaceAll(s, host, "<host>")
	}
	s = reJWT.ReplaceAllString(s, "<jwt>")
	s = reBearer.ReplaceAllString(s, "$1 <redacted>")
	s = reKV.ReplaceAllString(s, "$1=<redacted>")
	s = reIPv6.ReplaceAllString(s, "<ip>")
	s = reIPv4.ReplaceAllString(s, "<ip>")
	s = reLong.ReplaceAllString(s, "<token>")
	return s
}

// maskURL keeps scheme and path shape but drops host, credentials, query and
// fragment.
func maskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<url>"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return u.Scheme + "://<host>" + path
}

// Finding builds the redacted view of a finding. Evidence (request,
// response, matched payload, config lines) is deliberately omitted.
func Finding(f core.Finding) RedactedFinding {
	host := f.Asset.Host
	asset := f.Asset.Value
	switch f.Asset.Kind {
	case core.AssetURL:
		asset = maskURL(asset)
	case core.AssetRoute:
		asset = strings.TrimSpace(f.Asset.Method + " " + f.Asset.Path)
	case core.AssetFile:
		asset = f.Asset.File // repo-relative path; no contents
	default:
		asset = "<" + string(f.Asset.Kind) + ">"
	}
	var stacks []string
	for _, fx := range f.Remediation.How {
		stacks = append(stacks, fx.Stack)
	}
	return RedactedFinding{
		CheckID:    f.CheckID,
		Title:      Text(f.Title, host),
		Category:   f.Category.String(),
		Severity:   f.Severity.String(),
		Confidence: f.Confidence.String(),
		AssetKind:  string(f.Asset.Kind),
		Asset:      Text(asset, host),
		CWE:        f.CWE,
		OWASP:      f.OWASP,
		What:       Text(f.Remediation.What, host),
		Why:        Text(f.Remediation.Why, host),
		FixStacks:  stacks,
		Effort:     string(f.Remediation.Effort),
	}
}
