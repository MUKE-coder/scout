// Package headers checks HTTP security-hardening headers. Every check here is
// passive: it reads one ordinary GET response, shared across all checks in the
// scan via httpx.Get's per-scan memoization, and sends no attack traffic.
package headers

import (
	"context"
	"net/http"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/remediation"
)

func init() {
	core.Register(NoSniff{})
	core.Register(HSTS{})
	core.Register(Clickjacking{})
	core.Register(CSP{})
	core.Register(ReferrerPolicy{})
	core.Register(PermissionsPolicy{})
	core.Register(CookieFlags{})
	core.Register(ServerDisclosure{})
}

// header reads the target's base page once (memoized for the whole scan) and
// returns it, or (nil, nil, err). A repo-only target yields (nil, nil, nil) so
// every check short-circuits cleanly.
func page(ctx context.Context, t core.Target) (*httpx.Page, bool, error) {
	if t.URL == "" {
		return nil, false, nil
	}
	p, err := httpx.Get(ctx, t.URL)
	if err != nil {
		return nil, false, err
	}
	return p, true, nil
}

// has reports whether the named header is present and non-empty.
func has(h http.Header, name string) bool {
	return strings.TrimSpace(h.Get(name)) != ""
}

// NoSniff flags a missing X-Content-Type-Options: nosniff header.
type NoSniff struct{}

func (NoSniff) ID() string              { return "headers.nosniff" }
func (NoSniff) Category() core.Category { return core.CategoryHeaders }
func (NoSniff) Mode() core.Mode         { return core.ModePassive }
func (NoSniff) Description() string {
	return "Response is missing X-Content-Type-Options: nosniff"
}
func (NoSniff) OWASP() []string { return []string{"A05:2021"} }
func (NoSniff) ASVS() []string  { return []string{"V14.4.3"} }

func (NoSniff) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := page(ctx, t)
	if err != nil || !ok {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(p.Header.Get("X-Content-Type-Options")), "nosniff") {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "X-Content-Type-Options: nosniff is missing",
		Category:   core.CategoryHeaders,
		Severity:   core.SeverityLow,
		Confidence: core.ConfidenceConfirmed,
		Asset:      httpx.Asset(t, p.URL),
		Evidence:   core.Evidence{Request: p.Request, Response: p.Response},
		CWE:        []string{"CWE-693"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What:   "Responses do not send X-Content-Type-Options: nosniff.",
			Why:    "Browsers may guess a response's content type (MIME sniffing), so an uploaded or user-controlled file can be interpreted as script or stylesheet and executed.",
			How:    remediation.SetHeader("X-Content-Type-Options", "nosniff"),
			Effort: core.EffortS,
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
			},
		},
	}}, nil
}

// HSTS flags a missing Strict-Transport-Security header on an HTTPS target.
type HSTS struct{}

func (HSTS) ID() string              { return "headers.hsts" }
func (HSTS) Category() core.Category { return core.CategoryHeaders }
func (HSTS) Mode() core.Mode         { return core.ModePassive }
func (HSTS) Description() string {
	return "HTTPS response is missing Strict-Transport-Security (HSTS)"
}
func (HSTS) OWASP() []string { return []string{"A05:2021"} }
func (HSTS) ASVS() []string  { return []string{"V9.1.2"} }

func (HSTS) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := page(ctx, t)
	if err != nil || !ok {
		return nil, err
	}
	// HSTS only applies over HTTPS; a plaintext target has a different problem.
	if p.URL.Scheme != "https" {
		return nil, nil
	}
	if has(p.Header, "Strict-Transport-Security") {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "Strict-Transport-Security (HSTS) is missing",
		Category:   core.CategoryHeaders,
		Severity:   core.SeverityMedium,
		Confidence: core.ConfidenceConfirmed,
		Asset:      httpx.Asset(t, p.URL),
		Evidence:   core.Evidence{Request: p.Request, Response: p.Response},
		CWE:        []string{"CWE-319"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What:   "The site is served over HTTPS but does not send a Strict-Transport-Security header.",
			Why:    "Without HSTS a network attacker can downgrade the first request to HTTP and intercept or tamper with it (SSL stripping) before the browser learns to use HTTPS.",
			How:    remediation.SetHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
			Effort: core.EffortS,
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
			},
		},
	}}, nil
}

// Clickjacking flags a page that can be framed: no X-Frame-Options and no CSP
// frame-ancestors directive.
type Clickjacking struct{}

func (Clickjacking) ID() string              { return "headers.clickjacking" }
func (Clickjacking) Category() core.Category { return core.CategoryHeaders }
func (Clickjacking) Mode() core.Mode         { return core.ModePassive }
func (Clickjacking) Description() string {
	return "Page lacks clickjacking protection (X-Frame-Options / frame-ancestors)"
}
func (Clickjacking) OWASP() []string { return []string{"A05:2021"} }
func (Clickjacking) ASVS() []string  { return []string{"V14.4.7"} }

func (Clickjacking) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := page(ctx, t)
	if err != nil || !ok {
		return nil, err
	}
	if has(p.Header, "X-Frame-Options") {
		return nil, nil
	}
	if csp := p.Header.Get("Content-Security-Policy"); strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "Clickjacking protection is missing",
		Category:   core.CategoryHeaders,
		Severity:   core.SeverityMedium,
		Confidence: core.ConfidenceConfirmed,
		Asset:      httpx.Asset(t, p.URL),
		Evidence:   core.Evidence{Request: p.Request, Response: p.Response},
		CWE:        []string{"CWE-1021"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What:   "The response sends neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive.",
			Why:    "An attacker can embed the page in an invisible iframe on their own site and trick a logged-in user into clicking controls they cannot see (clickjacking).",
			How:    remediation.SetHeader("X-Frame-Options", "DENY"),
			Effort: core.EffortS,
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
			},
		},
	}}, nil
}

// CSP flags a missing Content-Security-Policy header.
type CSP struct{}

func (CSP) ID() string              { return "headers.csp" }
func (CSP) Category() core.Category { return core.CategoryHeaders }
func (CSP) Mode() core.Mode         { return core.ModePassive }
func (CSP) Description() string {
	return "Response is missing a Content-Security-Policy"
}
func (CSP) OWASP() []string { return []string{"A05:2021"} }
func (CSP) ASVS() []string  { return []string{"V14.4.6"} }

func (CSP) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := page(ctx, t)
	if err != nil || !ok {
		return nil, err
	}
	// A report-only policy enforces nothing, so treat it as absent.
	if has(p.Header, "Content-Security-Policy") {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "Content-Security-Policy is missing",
		Category:   core.CategoryHeaders,
		Severity:   core.SeverityMedium,
		Confidence: core.ConfidenceConfirmed,
		Asset:      httpx.Asset(t, p.URL),
		Evidence:   core.Evidence{Request: p.Request, Response: p.Response},
		CWE:        []string{"CWE-693"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What:   "No Content-Security-Policy header is sent, so the browser has no restriction on where scripts, styles and other resources may load from.",
			Why:    "A CSP is the main defense-in-depth control against cross-site scripting: without it, an injected <script> runs with no restriction on its source or inline execution.",
			How:    remediation.SetHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'"),
			Effort: core.EffortM,
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
			},
		},
	}}, nil
}

// ReferrerPolicy flags a missing Referrer-Policy header.
type ReferrerPolicy struct{}

func (ReferrerPolicy) ID() string              { return "headers.referrer-policy" }
func (ReferrerPolicy) Category() core.Category { return core.CategoryHeaders }
func (ReferrerPolicy) Mode() core.Mode         { return core.ModePassive }
func (ReferrerPolicy) Description() string {
	return "Response is missing a Referrer-Policy"
}
func (ReferrerPolicy) OWASP() []string { return []string{"A05:2021"} }
func (ReferrerPolicy) ASVS() []string  { return []string{"V14.4.5"} }

func (ReferrerPolicy) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := page(ctx, t)
	if err != nil || !ok {
		return nil, err
	}
	if has(p.Header, "Referrer-Policy") {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "Referrer-Policy is missing",
		Category:   core.CategoryHeaders,
		Severity:   core.SeverityLow,
		Confidence: core.ConfidenceConfirmed,
		Asset:      httpx.Asset(t, p.URL),
		Evidence:   core.Evidence{Request: p.Request, Response: p.Response},
		CWE:        []string{"CWE-200"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What:   "No Referrer-Policy header is sent, so the browser may attach the full URL as the Referer on outbound requests.",
			Why:    "URLs often carry sensitive data (tokens, IDs, internal paths). Without a Referrer-Policy that data leaks to third-party sites and analytics when a user follows a link or loads an external resource.",
			How:    remediation.SetHeader("Referrer-Policy", "strict-origin-when-cross-origin"),
			Effort: core.EffortS,
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
			},
		},
	}}, nil
}

// PermissionsPolicy flags a missing Permissions-Policy header.
type PermissionsPolicy struct{}

func (PermissionsPolicy) ID() string              { return "headers.permissions-policy" }
func (PermissionsPolicy) Category() core.Category { return core.CategoryHeaders }
func (PermissionsPolicy) Mode() core.Mode         { return core.ModePassive }
func (PermissionsPolicy) Description() string {
	return "Response is missing a Permissions-Policy"
}
func (PermissionsPolicy) OWASP() []string { return []string{"A05:2021"} }
func (PermissionsPolicy) ASVS() []string  { return []string{"V14.4.1"} }

func (PermissionsPolicy) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := page(ctx, t)
	if err != nil || !ok {
		return nil, err
	}
	if has(p.Header, "Permissions-Policy") {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "Permissions-Policy is missing",
		Category:   core.CategoryHeaders,
		Severity:   core.SeverityLow,
		Confidence: core.ConfidenceConfirmed,
		Asset:      httpx.Asset(t, p.URL),
		Evidence:   core.Evidence{Request: p.Request, Response: p.Response},
		CWE:        []string{"CWE-693"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What:   "No Permissions-Policy header is sent, so embedded content and scripts may request powerful browser features (camera, microphone, geolocation) unchecked.",
			Why:    "If the page is compromised by XSS or hosts third-party content, a Permissions-Policy limits the blast radius by denying access to sensitive device features.",
			How:    remediation.SetHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()"),
			Effort: core.EffortS,
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
			},
		},
	}}, nil
}

// ServerDisclosure flags a Server or X-Powered-By header that leaks a product
// and version. One finding per leaking header, distinguished by Location.
type ServerDisclosure struct{}

func (ServerDisclosure) ID() string              { return "headers.server-disclosure" }
func (ServerDisclosure) Category() core.Category { return core.CategoryHeaders }
func (ServerDisclosure) Mode() core.Mode         { return core.ModePassive }
func (ServerDisclosure) Description() string {
	return "Response leaks server software and version (Server / X-Powered-By)"
}
func (ServerDisclosure) OWASP() []string { return []string{"A05:2021"} }
func (ServerDisclosure) ASVS() []string  { return []string{"V14.3.3"} }

func (ServerDisclosure) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := page(ctx, t)
	if err != nil || !ok {
		return nil, err
	}
	var out []core.Finding
	// Deterministic order: fixed slice, not map iteration.
	for _, name := range []string{"Server", "X-Powered-By"} {
		v := strings.TrimSpace(p.Header.Get(name))
		if v == "" || !hasVersion(v) {
			continue
		}
		out = append(out, core.Finding{
			Title:      "Server software version disclosed in " + name,
			Category:   core.CategoryHeaders,
			Severity:   core.SeverityInfo,
			Confidence: core.ConfidenceConfirmed,
			Asset:      httpx.Asset(t, p.URL),
			Location:   name,
			Evidence:   core.Evidence{Request: p.Request, Response: p.Response, Matched: name + ": " + v},
			CWE:        []string{"CWE-200"},
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What:   "The " + name + " header advertises the exact software and version in use.",
				Why:    "A precise version lets an attacker look up known CVEs for it and skip straight to a working exploit. Hiding the version raises their cost without affecting users.",
				How:    suppressServerHeader(name),
				Effort: core.EffortS,
				References: []string{
					"https://owasp.org/www-project-secure-headers/",
				},
			},
		})
	}
	return out, nil
}

// hasVersion reports whether a header value contains a version-like token
// (a digit), which is what makes disclosure useful to an attacker. A bare
// "nginx" or "cloudflare" is not worth flagging.
func hasVersion(v string) bool {
	return strings.ContainsAny(v, "0123456789")
}

// suppressServerHeader returns fixes to hide or blank the leaking header.
func suppressServerHeader(name string) []core.Fix {
	if name == "X-Powered-By" {
		return []core.Fix{
			{Stack: remediation.Nginx, Language: "nginx", Code: `# hide the header entirely
proxy_hide_header X-Powered-By;`},
			{Stack: remediation.NextJS, Language: "js", Code: `// next.config.js
module.exports = { poweredByHeader: false };`},
			{Stack: remediation.Generic, Language: "text", Code: "Remove the X-Powered-By header in your framework or reverse proxy."},
		}
	}
	return []core.Fix{
		{Stack: remediation.Nginx, Language: "nginx", Code: `# nginx: drop the version, or use the headers-more module to remove it
server_tokens off;`},
		{Stack: remediation.Caddy, Language: "caddy", Code: `header -Server`},
		{Stack: remediation.Generic, Language: "text", Code: "Configure the server or reverse proxy to omit the software version from the Server header."},
	}
}
