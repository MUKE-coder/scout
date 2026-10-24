// Package framework runs framework-specific exposure checks, gated by the stack
// Scout detects on the target. It only probes endpoints relevant to the
// detected framework (e.g. Spring actuators on a Spring/Java app, WordPress
// REST/XML-RPC on WordPress), so a Next.js app is never probed for Spring.
//
// All checks are safe-mode: ordinary GETs through the guarded client, each
// self-validating its response; no attack payloads.
package framework

import (
	"context"
	"net/url"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/intel/stack"
)

func init() { core.Register(Exposure{}) }

type Exposure struct{}

func (Exposure) ID() string              { return "app.framework-exposure" }
func (Exposure) Category() core.Category { return core.CategoryApp }
func (Exposure) Mode() core.Mode         { return core.ModeSafe }
func (Exposure) Description() string {
	return "A framework-specific endpoint or debug surface is exposed"
}
func (Exposure) OWASP() []string { return []string{"A05:2021"} }
func (Exposure) ASVS() []string  { return []string{"V14.3.2"} }

func (c Exposure) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.URL == "" {
		return nil, nil
	}
	// Detect the stack from the live page (and the repo, if present).
	var comps []core.StackComponent
	if page, err := httpx.Get(ctx, t.URL); err == nil && page != nil {
		comps = stack.DetectFromPage(page.Header, page.Body)
	}
	if t.Repo != "" {
		comps = append(comps, stack.Detect(t, nil)...)
	}
	if len(comps) == 0 {
		return nil, nil
	}

	var out []core.Finding
	if stack.Has(comps, "WordPress") {
		out = append(out, wordpress(ctx, t)...)
	}
	if stack.Has(comps, "Laravel") {
		out = append(out, laravel(ctx, t)...)
	}
	if stack.Has(comps, "Spring") || stack.Has(comps, "Spring Boot") || stack.Has(comps, "Java") {
		out = append(out, spring(ctx, t)...)
	}
	return out, nil
}

// probe GETs a path and returns the page when it is 200 and the body contains
// the signature (case-insensitive), else nil.
func probe(ctx context.Context, t core.Target, path, signature string) *httpx.Page {
	u, err := httpx.Resolve(t, path)
	if err != nil {
		return nil
	}
	page, err := httpx.Get(ctx, u.String())
	if err != nil || page.Status < 200 || page.Status > 299 {
		return nil
	}
	if signature != "" && !strings.Contains(strings.ToLower(string(page.Body)), strings.ToLower(signature)) {
		return nil
	}
	return page
}

func assetFor(t core.Target, raw string) core.Asset {
	u, err := url.Parse(raw)
	if err != nil {
		return core.Asset{Kind: core.AssetURL, Value: raw, Criticality: t.Criticality}
	}
	return httpx.Asset(t, u)
}

func finding(t core.Target, p *httpx.Page, title string, sev core.Severity, cwe, owasp, what, why, fix string) core.Finding {
	return core.Finding{
		Title:      title,
		Category:   core.CategoryApp,
		Severity:   sev,
		Confidence: core.ConfidenceConfirmed,
		Asset:      assetFor(t, p.URL.String()),
		Location:   p.URL.EscapedPath(),
		Evidence:   core.Evidence{Request: p.Request, Matched: "reachable and returned a matching response"},
		CWE:        []string{cwe},
		OWASP:      []string{owasp},
		Remediation: core.Remediation{
			What:   what,
			Why:    why,
			How:    []core.Fix{{Stack: "generic", Language: "text", Code: fix}},
			Effort: core.EffortS,
		},
	}
}

// --- WordPress -------------------------------------------------------------

func wordpress(ctx context.Context, t core.Target) []core.Finding {
	var out []core.Finding
	if p := probe(ctx, t, "/wp-json/wp/v2/users", `"slug"`); p != nil {
		out = append(out, finding(t, p,
			"WordPress REST API exposes the user list (enumeration)", core.SeverityMedium, "CWE-200", "A01:2021",
			"The WordPress REST API returns the list of users (with slugs/usernames) to anonymous callers.",
			"Attackers harvest valid usernames for password-spraying and targeted phishing.",
			"Restrict /wp-json/wp/v2/users (require auth), or disable user endpoints with a plugin/filter (rest_endpoints)."))
	}
	if p := probe(ctx, t, "/xmlrpc.php", "xml-rpc server accepts post"); p != nil {
		out = append(out, finding(t, p,
			"WordPress XML-RPC is enabled", core.SeverityLow, "CWE-284", "A05:2021",
			"xmlrpc.php is reachable; it enables pingback abuse and credential brute-forcing via system.multicall.",
			"XML-RPC is a common brute-force and DDoS amplification vector.",
			"Disable XML-RPC if unused (block xmlrpc.php at the web server, or a disable-xmlrpc plugin)."))
	}
	return out
}

// --- Laravel ---------------------------------------------------------------

func laravel(ctx context.Context, t core.Target) []core.Finding {
	var out []core.Finding
	if p := probe(ctx, t, "/telescope/requests", "telescope"); p != nil {
		out = append(out, finding(t, p,
			"Laravel Telescope dashboard is exposed", core.SeverityHigh, "CWE-200", "A05:2021",
			"Telescope (the Laravel debug/monitoring dashboard) is reachable publicly.",
			"It exposes requests, queries, mail, cache and exceptions — including secrets and user data.",
			"Restrict Telescope to local/authorized users (TelescopeServiceProvider gate) or disable it in production."))
	}
	if p := probe(ctx, t, "/_ignition/health-check", "can_execute_commands"); p != nil {
		out = append(out, finding(t, p,
			"Laravel Ignition debug tool is exposed", core.SeverityHigh, "CWE-489", "A05:2021",
			"Ignition's debug endpoints are reachable, which indicates debug mode is on in production.",
			"Ignition has had remote-code-execution flaws (e.g. CVE-2021-3129); debug mode leaks config and stack traces.",
			"Set APP_DEBUG=false in production and remove/upgrade facade/ignition; never expose _ignition."))
	}
	return out
}

// --- Spring Boot -----------------------------------------------------------

func spring(ctx context.Context, t core.Target) []core.Finding {
	var out []core.Finding
	// Sensitive actuators first.
	for _, a := range []struct{ path, name, sig string }{
		{"/actuator/env", "env", `"activeprofiles"`},
		{"/actuator/heapdump", "heapdump", ""},
		{"/actuator/configprops", "configprops", `"contexts"`},
	} {
		sig := a.sig
		if a.name == "heapdump" {
			sig = "" // binary; presence (200) is enough
		}
		if p := probe(ctx, t, a.path, sig); p != nil {
			out = append(out, finding(t, p,
				"Spring Boot actuator exposed: "+a.name, core.SeverityHigh, "CWE-200", "A05:2021",
				"The Spring Boot actuator endpoint "+a.path+" is reachable without authentication.",
				"Sensitive actuators leak environment variables, config (often with secrets) and full heap dumps.",
				"Secure actuators: expose only /health, require auth (Spring Security) on the actuator endpoints, and never expose env/heapdump/configprops publicly."))
		}
	}
	if len(out) == 0 {
		if p := probe(ctx, t, "/actuator", `"_links"`); p != nil {
			out = append(out, finding(t, p,
				"Spring Boot actuator index is exposed", core.SeverityMedium, "CWE-200", "A05:2021",
				"The Spring Boot /actuator index is reachable without authentication.",
				"It lists the available management endpoints, several of which can leak secrets or config.",
				"Restrict actuator exposure (management.endpoints.web.exposure.include) and require auth on them."))
		}
	}
	return out
}
