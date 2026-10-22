// Package infodisc flags information disclosure: verbose error pages / stack
// traces that leak internals, and GraphQL schema introspection left enabled.
// Checks are safe-mode: they send ordinary GET requests (through the guarded
// client) and read the responses; they send no attack payloads.
package infodisc

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

func init() {
	core.Register(VerboseErrors{})
	core.Register(GraphQLIntrospection{})
}

// --- verbose errors / stack traces -------------------------------------

type VerboseErrors struct{}

func (VerboseErrors) ID() string              { return "app.info-disclosure" }
func (VerboseErrors) Category() core.Category { return core.CategoryApp }
func (VerboseErrors) Mode() core.Mode         { return core.ModeSafe }
func (VerboseErrors) Description() string     { return "A page leaks a stack trace or verbose error" }
func (VerboseErrors) OWASP() []string         { return []string{"A05:2021"} }
func (VerboseErrors) ASVS() []string          { return []string{"V7.4.1"} }

// stackSignatures are framework/runtime error fingerprints that should never
// reach a user.
var stackSignatures = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`goroutine \d+ \[`), "Go panic stack trace"},
	{regexp.MustCompile(`Traceback \(most recent call last\)`), "Python traceback"},
	{regexp.MustCompile(`at [\w.$]+ \(.*:\d+:\d+\)`), "Node.js stack trace"},
	{regexp.MustCompile(`\bjava\.lang\.[A-Za-z.]+Exception`), "Java exception"},
	{regexp.MustCompile(`(?i)(SQLSTATE|SQL syntax|ORA-\d{5}|psql:|Npgsql|unterminated quoted string)`), "database error"},
	{regexp.MustCompile(`(?i)<b>(Fatal error|Warning)</b>.*on line \d+`), "PHP error"},
	{regexp.MustCompile(`(?i)Microsoft \.NET Framework.*Exception|Server Error in '/' Application`), ".NET error page"},
}

// errorPaths are requested to try to provoke an unhandled error.
var errorPaths = []string{"/", "/'", "/%ff", "/api/__scout_probe__", "/?id[]=1"}

func (VerboseErrors) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.URL == "" {
		return nil, nil
	}
	var out []core.Finding
	reported := map[string]bool{}
	for _, p := range errorPaths {
		u, err := httpx.Resolve(t, p)
		if err != nil {
			continue
		}
		page, err := httpx.Get(ctx, u.String())
		if err != nil {
			continue
		}
		body := string(page.Body)
		for _, sig := range stackSignatures {
			if m := sig.re.FindString(body); m != "" && !reported[sig.what] {
				reported[sig.what] = true
				out = append(out, core.Finding{
					Title:      "Verbose error discloses internals: " + sig.what,
					Category:   core.CategoryApp,
					Severity:   core.SeverityLow,
					Confidence: core.ConfidenceConfirmed,
					Asset:      httpx.Asset(t, page.URL),
					Location:   sig.what,
					Evidence:   core.Evidence{Request: page.Request, Matched: trunc(m)},
					CWE:        []string{"CWE-209"},
					OWASP:      []string{"A05:2021"},
					Remediation: core.Remediation{
						What:       "The application returns stack traces or verbose runtime errors to clients.",
						Why:        "Stack traces reveal file paths, framework and library versions, SQL and internal structure that make further attacks easier.",
						How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Return generic error pages in production, log the detail server-side only, and disable debug mode."}},
						Effort:     core.EffortS,
						References: []string{"https://cwe.mitre.org/data/definitions/209.html"},
					},
				})
			}
		}
	}
	return out, nil
}

// --- GraphQL introspection ---------------------------------------------

type GraphQLIntrospection struct{}

func (GraphQLIntrospection) ID() string              { return "api.graphql-introspection" }
func (GraphQLIntrospection) Category() core.Category { return core.CategoryAPI }
func (GraphQLIntrospection) Mode() core.Mode         { return core.ModeSafe }
func (GraphQLIntrospection) Description() string     { return "GraphQL schema introspection is enabled" }
func (GraphQLIntrospection) OWASP() []string         { return []string{"A05:2021"} }

const introspectionQuery = "{__schema{queryType{name}types{name}}}"

var graphqlPaths = []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}

func (GraphQLIntrospection) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.URL == "" {
		return nil, nil
	}
	for _, p := range graphqlPaths {
		u, err := httpx.Resolve(t, p)
		if err != nil {
			continue
		}
		q := url.Values{"query": {introspectionQuery}}
		probe := u.String() + "?" + q.Encode()
		page, err := httpx.Get(ctx, probe)
		if err != nil || page.Status != 200 {
			continue
		}
		body := string(page.Body)
		if !strings.Contains(body, "__schema") && !strings.Contains(body, "queryType") {
			continue
		}
		return []core.Finding{{
			Title:      "GraphQL introspection is enabled at " + p,
			Category:   core.CategoryAPI,
			Severity:   core.SeverityLow,
			Confidence: core.ConfidenceConfirmed,
			Asset:      httpx.Asset(t, page.URL),
			Location:   p,
			Evidence:   core.Evidence{Request: page.Request, Notes: "introspection query returned a schema"},
			CWE:        []string{"CWE-200"},
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What:       "The GraphQL endpoint answers introspection queries, exposing the full schema.",
				Why:        "Attackers map every type, query and mutation to find sensitive operations and craft precise attacks.",
				How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Disable introspection in production, require authentication on the GraphQL endpoint, and add query depth/complexity limits."}},
				Effort:     core.EffortS,
				References: []string{"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"},
			},
		}}, nil
	}
	return nil, nil
}

func trunc(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
