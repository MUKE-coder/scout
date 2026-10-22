// Package clientside flags client-side integrity problems in a page's HTML:
// cross-origin scripts and stylesheets loaded without Subresource Integrity,
// and mixed content (an HTTPS page pulling resources over plain HTTP). Both
// checks are safe-mode: they fetch the page with an ordinary GET and parse the
// returned HTML; they send no attack payloads.
package clientside

import (
	"context"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

func init() {
	core.Register(MissingSRI{})
	core.Register(MixedContent{})
}

// resource is one external thing the page pulls in.
type resource struct {
	tag       string   // "script", "link", "img", ...
	rel       string   // link rel, lowercased
	raw       string   // the src/href/data value as written
	resolved  *url.URL // resolved against the page URL (nil if unparseable)
	integrity bool     // an integrity attribute is present
}

// parseResources walks the HTML and returns every subresource reference. page
// is the resolved page URL, used to resolve relative references.
func parseResources(body []byte, page *url.URL) []resource {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	var out []resource
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if r, ok := resourceFromNode(n, page); ok {
				out = append(out, r)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

// urlAttrs names, per tag, the attribute that holds its resource URL.
var urlAttrs = map[string]string{
	"script": "src",
	"link":   "href",
	"img":    "src",
	"iframe": "src",
	"audio":  "src",
	"video":  "src",
	"source": "src",
	"embed":  "src",
	"object": "data",
}

func resourceFromNode(n *html.Node, page *url.URL) (resource, bool) {
	attr, ok := urlAttrs[n.Data]
	if !ok {
		return resource{}, false
	}
	r := resource{tag: n.Data}
	var raw string
	for _, a := range n.Attr {
		switch strings.ToLower(a.Key) {
		case attr:
			raw = strings.TrimSpace(a.Val)
		case "rel":
			r.rel = strings.ToLower(strings.TrimSpace(a.Val))
		case "integrity":
			if strings.TrimSpace(a.Val) != "" {
				r.integrity = true
			}
		}
	}
	if raw == "" {
		return resource{}, false
	}
	r.raw = raw
	if ref, err := url.Parse(raw); err == nil && page != nil {
		r.resolved = page.ResolveReference(ref)
	}
	return r, true
}

// --- missing Subresource Integrity -------------------------------------

type MissingSRI struct{}

func (MissingSRI) ID() string              { return "app.missing-sri" }
func (MissingSRI) Category() core.Category { return core.CategoryApp }
func (MissingSRI) Mode() core.Mode         { return core.ModeSafe }
func (MissingSRI) Description() string {
	return "A cross-origin script or stylesheet loads without Subresource Integrity"
}
func (MissingSRI) OWASP() []string { return []string{"A08:2021"} }
func (MissingSRI) ASVS() []string  { return []string{"V14.2.3"} }

func (c MissingSRI) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.URL == "" {
		return nil, nil
	}
	page, err := httpx.Get(ctx, t.URL)
	if err != nil || page == nil {
		return nil, err
	}
	var out []core.Finding
	seen := map[string]bool{}
	for _, r := range parseResources(page.Body, page.URL) {
		// SRI applies to scripts and stylesheet links only.
		if r.tag != "script" && !(r.tag == "link" && r.rel == "stylesheet") {
			continue
		}
		if r.integrity || r.resolved == nil {
			continue
		}
		if !crossOrigin(page.URL, r.resolved) {
			continue // same-origin resources don't need SRI
		}
		if seen[r.raw] {
			continue
		}
		seen[r.raw] = true
		kind := "script"
		if r.tag == "link" {
			kind = "stylesheet"
		}
		out = append(out, core.Finding{
			Title:       "Cross-origin " + kind + " without Subresource Integrity",
			Category:    core.CategoryApp,
			Severity:    core.SeverityMedium,
			Confidence:  core.ConfidenceConfirmed,
			Asset:       httpx.Asset(t, page.URL),
			Location:    r.resolved.String(),
			Evidence:    core.Evidence{Matched: "<" + r.tag + "> " + r.raw + " has no integrity attribute"},
			CWE:         []string{"CWE-353"},
			OWASP:       []string{"A08:2021"},
			Remediation: remediationSRI,
		})
	}
	return out, nil
}

var remediationSRI = core.Remediation{
	What: "A script or stylesheet is loaded from another origin (e.g. a CDN) without an integrity hash.",
	Why:  "If that origin is compromised or hijacked, it can serve malicious code that runs with your page's full privileges, and the browser has no way to notice the swap.",
	How: []core.Fix{
		{Stack: "html", Language: "html", Code: `<script src="https://cdn.example.com/lib.js"
        integrity="sha384-<hash>" crossorigin="anonymous"></script>`},
	},
	Effort:     core.EffortS,
	References: []string{"https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"},
}

// --- mixed content ------------------------------------------------------

type MixedContent struct{}

func (MixedContent) ID() string              { return "app.mixed-content" }
func (MixedContent) Category() core.Category { return core.CategoryApp }
func (MixedContent) Mode() core.Mode         { return core.ModeSafe }
func (MixedContent) Description() string {
	return "An HTTPS page loads resources over plain HTTP (mixed content)"
}
func (MixedContent) OWASP() []string { return []string{"A05:2021"} }
func (MixedContent) ASVS() []string  { return []string{"V9.1.1"} }

// activeTags load executable/visual content whose HTTP delivery is dangerous
// (the browser blocks or should block it). Others are passive mixed content.
var activeTags = map[string]bool{"script": true, "link": true, "iframe": true, "object": true, "embed": true}

func (c MixedContent) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.URL == "" {
		return nil, nil
	}
	page, err := httpx.Get(ctx, t.URL)
	if err != nil || page == nil {
		return nil, err
	}
	// Only meaningful for an HTTPS page.
	if page.URL == nil || page.URL.Scheme != "https" {
		return nil, nil
	}
	var out []core.Finding
	seen := map[string]bool{}
	for _, r := range parseResources(page.Body, page.URL) {
		if r.resolved == nil || r.resolved.Scheme != "http" {
			continue
		}
		if seen[r.raw] {
			continue
		}
		seen[r.raw] = true
		active := activeTags[r.tag]
		sev := core.SeverityLow
		if active {
			sev = core.SeverityHigh // active mixed content can run attacker code
		}
		kind := "passive"
		if active {
			kind = "active"
		}
		out = append(out, core.Finding{
			Title:       "Mixed content: HTTPS page loads http:// resource (" + kind + ")",
			Category:    core.CategoryApp,
			Severity:    sev,
			Confidence:  core.ConfidenceConfirmed,
			Asset:       httpx.Asset(t, page.URL),
			Location:    r.resolved.String(),
			Evidence:    core.Evidence{Matched: "<" + r.tag + "> loads " + r.raw + " over HTTP"},
			CWE:         []string{"CWE-311"},
			OWASP:       []string{"A05:2021"},
			Remediation: remediationMixed,
		})
	}
	return out, nil
}

var remediationMixed = core.Remediation{
	What: "A page served over HTTPS pulls in scripts, styles, frames or media over plain HTTP.",
	Why:  "The HTTP resources travel unencrypted and can be read or rewritten by a network attacker; active ones (scripts/frames) then run in the secure page's context.",
	How: []core.Fix{
		{Stack: "generic", Language: "text", Code: "Load every subresource over HTTPS (use protocol-relative or absolute https:// URLs), and add a Content-Security-Policy with 'upgrade-insecure-requests' to catch the rest."},
	},
	Effort:     core.EffortM,
	References: []string{"https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"},
}

// crossOrigin reports whether res is served from a different origin than page.
func crossOrigin(page, res *url.URL) bool {
	if page == nil || res == nil {
		return false
	}
	return !strings.EqualFold(page.Scheme, res.Scheme) ||
		!strings.EqualFold(page.Host, res.Host)
}
