package headers

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

// CookieFlags flags Set-Cookie headers that lack hardening flags. It emits one
// finding per weak cookie, keyed by cookie name in Location, so each can be
// tracked and fixed independently across scans.
type CookieFlags struct{}

func (CookieFlags) ID() string              { return "headers.cookie-flags" }
func (CookieFlags) Category() core.Category { return core.CategoryHeaders }
func (CookieFlags) Mode() core.Mode         { return core.ModePassive }
func (CookieFlags) Description() string {
	return "Set-Cookie is missing HttpOnly / Secure / SameSite flags"
}
func (CookieFlags) OWASP() []string { return []string{"A05:2021"} }
func (CookieFlags) ASVS() []string  { return []string{"V3.4.1", "V3.4.2", "V3.4.3"} }

func (CookieFlags) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := page(ctx, t)
	if err != nil || !ok {
		return nil, err
	}
	https := p.URL.Scheme == "https"

	// Sort cookies by name for deterministic output.
	cookies := append([]*http.Cookie(nil), p.Cookies...)
	sort.SliceStable(cookies, func(i, j int) bool { return cookies[i].Name < cookies[j].Name })

	var out []core.Finding
	for _, c := range cookies {
		var missing []string
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		// Secure can only be set meaningfully over HTTPS; flag its absence there.
		if https && !c.Secure {
			missing = append(missing, "Secure")
		}
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == http.SameSiteDefaultMode {
			missing = append(missing, "SameSite")
		}
		if len(missing) == 0 {
			continue
		}
		sev := core.SeverityLow
		// A session-style cookie with no HttpOnly is the dangerous case.
		if !c.HttpOnly && looksLikeSession(c.Name) {
			sev = core.SeverityMedium
		}
		out = append(out, core.Finding{
			Title:      "Cookie " + c.Name + " is missing " + strings.Join(missing, ", "),
			Category:   core.CategoryHeaders,
			Severity:   sev,
			Confidence: core.ConfidenceConfirmed,
			Asset:      httpx.Asset(t, p.URL),
			Location:   c.Name,
			Evidence:   core.Evidence{Request: p.Request, Response: p.Response, Matched: redactCookie(c.Raw)},
			CWE:        cookieCWE(missing),
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What:   "The cookie " + c.Name + " is set without " + strings.Join(missing, ", ") + ".",
				Why:    cookieWhy(missing),
				How:    cookieFix(c.Name, missing, https),
				Effort: core.EffortS,
				References: []string{
					"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
				},
			},
		})
	}
	return out, nil
}

func looksLikeSession(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"sess", "sid", "token", "auth", "jwt", "login"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// redactCookie strips the cookie value from the raw Set-Cookie line, keeping
// only the name and attributes, so evidence never carries a live session token.
func redactCookie(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.SplitN(raw, ";", 2)
	nv := strings.SplitN(parts[0], "=", 2)
	out := nv[0] + "=<redacted>"
	if len(parts) == 2 {
		out += ";" + parts[1]
	}
	return out
}

func cookieCWE(missing []string) []string {
	for _, m := range missing {
		if m == "HttpOnly" {
			return []string{"CWE-1004"} // sensitive cookie without HttpOnly
		}
	}
	for _, m := range missing {
		if m == "Secure" {
			return []string{"CWE-614"} // sensitive cookie without Secure
		}
	}
	return []string{"CWE-1275"} // SameSite
}

func cookieWhy(missing []string) string {
	switch {
	case contains(missing, "HttpOnly"):
		return "Without HttpOnly, any cross-site scripting on the site can read the cookie from document.cookie and steal the session."
	case contains(missing, "Secure"):
		return "Without Secure, the cookie is sent over plaintext HTTP and a network attacker can capture it."
	default:
		return "Without SameSite, the cookie is attached to cross-site requests, enabling cross-site request forgery (CSRF)."
	}
}

func cookieFix(name string, missing []string, https bool) []core.Fix {
	attrs := "HttpOnly; SameSite=Lax"
	if https {
		attrs = "Secure; " + attrs
	}
	return []core.Fix{
		{Stack: "gin", Language: "go", Code: `// gin: set the flags explicitly
c.SetSameSite(http.SameSiteLaxMode)
c.SetCookie(` + quote(name) + `, value, maxAge, "/", "", ` + boolStr(https) + `, true) // secure, httpOnly`},
		{Stack: "generic", Language: "text", Code: "Set-Cookie: " + name + "=...; " + attrs},
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

func quote(s string) string { return `"` + s + `"` }

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
