// Package crawl spiders a target from its base URL to discover pages, forms
// and API endpoints, and flags state-changing forms that carry no CSRF
// token. It is safe-mode: it only issues GET requests (through the guarded,
// rate-limited client) and never submits a form or sends a payload. All
// fetches stay on the target's own host; scope and rate limits are enforced
// by the engine's client.
package crawl

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

func init() { core.Register(Forms{}) }

// Crawl limits. Kept modest so a scan stays quick and polite.
const (
	maxPages = 40
	maxDepth = 2
)

// Form is a discovered HTML form.
type Form struct {
	Action    string
	Method    string
	HasCSRF   bool
	PageURL   string
	FieldList []string
}

// Result is the crawl output, memoized for the whole scan so other checks
// (now or later) can reuse it without re-fetching.
type Result struct {
	Pages     []string
	Forms     []Form
	Endpoints []string // same-host URLs that look like API or data endpoints
}

// Forms flags state-changing forms with no apparent CSRF token.
type Forms struct{}

func (Forms) ID() string              { return "app.csrf-form" }
func (Forms) Category() core.Category { return core.CategoryApp }
func (Forms) Mode() core.Mode         { return core.ModeSafe }
func (Forms) Description() string {
	return "A state-changing form has no CSRF token field"
}
func (Forms) OWASP() []string { return []string{"A01:2021"} }
func (Forms) ASVS() []string  { return []string{"V4.2.2"} }

func (Forms) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.URL == "" {
		return nil, nil
	}
	res, err := Crawl(ctx, t)
	if err != nil {
		return nil, err
	}
	var out []core.Finding
	for _, f := range res.Forms {
		if f.HasCSRF || !stateChanging(f.Method) {
			continue
		}
		u, perr := url.Parse(f.PageURL)
		if perr != nil {
			continue
		}
		out = append(out, core.Finding{
			Title:      "Form without a CSRF token: " + formLabel(f),
			Category:   core.CategoryApp,
			Severity:   core.SeverityMedium,
			Confidence: core.ConfidenceLikely, // a token may travel via header/JS
			Asset:      httpx.Asset(t, u),
			Location:   strings.ToUpper(f.Method) + " " + f.Action,
			Evidence: core.Evidence{
				Notes: fmt.Sprintf("Form on %s submits to %q via %s with fields [%s] and no hidden CSRF-token field.",
					f.PageURL, f.Action, strings.ToUpper(f.Method), strings.Join(f.FieldList, ", ")),
			},
			CWE:   []string{"CWE-352"},
			OWASP: []string{"A01:2021"},
			Remediation: core.Remediation{
				What: "A form that changes state has no anti-CSRF token, so another site can submit it on a logged-in user's behalf.",
				Why:  "Without a per-session CSRF token (or SameSite cookies plus an origin check), an attacker page can forge this request using the victim's cookies.",
				How: []core.Fix{
					{Stack: "gin", Language: "go", Code: "// Add CSRF middleware (e.g. gorilla/csrf or a double-submit cookie)\n// and render the token as a hidden field in every state-changing form.\nr.Use(csrf.Protect([]byte(secret), csrf.Secure(true)))"},
					{Stack: "generic", Language: "text", Code: "Set SameSite=Lax or Strict on session cookies, verify the Origin/Referer header on state-changing requests, and embed a per-session CSRF token as a hidden field."},
				},
				Effort:     core.EffortM,
				References: []string{"https://owasp.org/www-community/attacks/csrf", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"},
			},
		})
	}
	return out, nil
}

// Crawl spiders the target (GET only) and returns discovered pages, forms and
// endpoints. Memoized per scan.
func Crawl(ctx context.Context, t core.Target) (*Result, error) {
	return core.Memo(ctx, "crawl:"+t.URL, func() (*Result, error) {
		base, err := url.Parse(t.URL)
		if err != nil {
			return nil, err
		}
		res := &Result{}
		seen := map[string]bool{}
		endpoints := map[string]bool{}
		type item struct {
			u     *url.URL
			depth int
		}
		queue := []item{{base, 0}}
		seen[canonical(base)] = true

		for len(queue) > 0 && len(res.Pages) < maxPages {
			cur := queue[0]
			queue = queue[1:]

			page, err := httpx.Get(ctx, cur.u.String())
			if err != nil {
				continue // a dead link is not a crawl failure
			}
			res.Pages = append(res.Pages, cur.u.String())
			if !isHTML(page) {
				continue
			}
			doc, err := html.Parse(strings.NewReader(string(page.Body)))
			if err != nil {
				continue
			}
			links, forms := extract(doc, page.URL)
			for _, f := range forms {
				res.Forms = append(res.Forms, f)
				if a, e := page.URL.Parse(f.Action); e == nil && sameHost(base, a) {
					endpoints[canonical(a)] = true
				}
			}
			if cur.depth >= maxDepth {
				continue
			}
			for _, l := range links {
				if !sameHost(base, l) {
					continue
				}
				key := canonical(l)
				if looksLikeEndpoint(l) {
					endpoints[key] = true
				}
				if !seen[key] && len(seen) < maxPages*4 {
					seen[key] = true
					queue = append(queue, item{l, cur.depth + 1})
				}
			}
		}
		res.Endpoints = sortedKeys(endpoints)
		return res, nil
	})
}

// extract pulls same-document links and forms from a parsed page.
func extract(doc *html.Node, pageURL *url.URL) (links []*url.URL, forms []Form) {
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				if href := attr(n, "href"); href != "" {
					if u, err := pageURL.Parse(href); err == nil {
						u.Fragment = ""
						links = append(links, u)
					}
				}
			case "form":
				forms = append(forms, parseForm(n, pageURL))
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return links, forms
}

var csrfHint = []string{"csrf", "xsrf", "_token", "authenticity_token", "nonce", "anti-forgery", "requestverificationtoken"}

func parseForm(n *html.Node, pageURL *url.URL) Form {
	f := Form{Method: strings.ToLower(attr(n, "method")), Action: attr(n, "action"), PageURL: pageURL.String()}
	if f.Method == "" {
		f.Method = "get"
	}
	if f.Action == "" {
		f.Action = pageURL.String()
	}
	var walk func(*html.Node)
	walk = func(c *html.Node) {
		if c.Type == html.ElementNode && (c.Data == "input" || c.Data == "textarea" || c.Data == "select") {
			name := attr(c, "name")
			if name != "" {
				f.FieldList = append(f.FieldList, name)
			}
			hay := strings.ToLower(name + " " + attr(c, "id"))
			for _, h := range csrfHint {
				if strings.Contains(hay, h) {
					f.HasCSRF = true
				}
			}
		}
		for ch := c.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(n)
	return f
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func stateChanging(method string) bool {
	switch strings.ToLower(method) {
	case "post", "put", "patch", "delete":
		return true
	}
	return false
}

func sameHost(base, u *url.URL) bool {
	return u.Host == "" || strings.EqualFold(u.Hostname(), base.Hostname())
}

func isHTML(p *httpx.Page) bool {
	return strings.Contains(strings.ToLower(p.Header.Get("Content-Type")), "text/html")
}

// looksLikeEndpoint flags URLs that resemble API or data endpoints.
func looksLikeEndpoint(u *url.URL) bool {
	p := strings.ToLower(u.EscapedPath())
	if strings.Contains(p, "/api/") || strings.HasPrefix(p, "/api") || strings.Contains(p, "/v1/") || strings.Contains(p, "/v2/") || strings.Contains(p, "/graphql") {
		return true
	}
	for _, ext := range []string{".json", ".xml"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func canonical(u *url.URL) string {
	c := *u
	c.Fragment = ""
	return strings.ToLower(c.Scheme) + "://" + strings.ToLower(c.Host) + c.EscapedPath()
}

func formLabel(f Form) string {
	if len(f.FieldList) == 0 {
		return f.Action
	}
	return f.Action + " (" + strings.Join(f.FieldList, ", ") + ")"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
