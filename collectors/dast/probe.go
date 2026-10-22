package dast

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

// injectable is one testable spot: a GET endpoint carrying a query parameter
// we can mutate. DAST discovers these from the crawl's pages, forms (GET only)
// and endpoints. We only ever test GET query parameters here — submitting a
// form (POST/PUT/…) is state-changing and is left to checks that have test
// accounts and non-destructive guarantees.
type injectable struct {
	rawURL string // the page/endpoint URL, with its existing query
	param  string // the parameter name to mutate
}

// nameHints are parameter names worth testing for a given class, so a scan
// stays focused and polite rather than fuzzing every parameter blindly.
var (
	redirectParams = []string{"url", "next", "redirect", "redirect_uri", "return", "returnurl", "return_to", "dest", "destination", "continue", "goto", "r", "u"}
	fileParams     = []string{"file", "path", "page", "template", "doc", "document", "download", "name", "filename", "dir", "folder", "include", "view"}
	urlParams      = []string{"url", "uri", "target", "dest", "callback", "webhook", "feed", "endpoint", "proxy", "fetch", "image", "img", "src", "host"}
)

// gather collects injectable (url, param) spots from the crawl result. When a
// URL already has query parameters, each is a spot. When a URL has none but its
// path looks relevant, we propose the hint parameters for the class so a bare
// endpoint still gets tested. Results are deterministic (sorted, de-duped).
func gather(urls []string, hints []string) []injectable {
	seen := map[string]bool{}
	var out []injectable
	add := func(raw, p string) {
		key := raw + "\x00" + p
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, injectable{rawURL: raw, param: p})
	}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		q := u.Query()
		if len(q) > 0 {
			// Existing parameters, in sorted order.
			for _, p := range sortedParamNames(q) {
				add(raw, p)
			}
			continue
		}
		// No query: offer the class hint params on this URL.
		for _, p := range hints {
			add(raw, p)
		}
	}
	return out
}

// allParams returns every existing query parameter across the crawled URLs,
// as injectable spots. Unlike gather, it does not synthesize hint parameters:
// injection checks test parameters the app actually uses. Deterministic.
func allParams(res *crawlResult) []injectable {
	seen := map[string]bool{}
	var out []injectable
	for _, raw := range targetsFor(res) {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for _, p := range sortedParamNames(u.Query()) {
			key := raw + "\x00" + p
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, injectable{rawURL: raw, param: p})
		}
	}
	return out
}

// httpxPage aliases the httpx page type so dast.go need not import httpx.
type httpxPage = httpx.Page

// isHTMLResponse reports whether a page is served as HTML.
func isHTMLResponse(p *httpx.Page) bool {
	return strings.Contains(strings.ToLower(p.Header.Get("Content-Type")), "text/html")
}

// targetsFor returns the set of URLs to test: crawled pages plus endpoints.
func targetsFor(res *crawlResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, lst := range [][]string{res.Pages, res.Endpoints} {
		for _, u := range lst {
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}

// withParam returns rawURL with param set to value, replacing any existing
// value for that param and preserving the rest of the query.
func withParam(rawURL, param, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// canary returns an unlikely-to-collide marker string with the given prefix,
// e.g. "scoutx9f3a1c2b". It is benign: letters and digits only, no markup.
func canary(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// get fetches a mutated URL through the guarded client (never a bare client).
func get(ctx context.Context, rawURL string) (*httpx.Page, error) {
	return httpx.Do(ctx, http.MethodGet, rawURL, nil)
}

// hop performs a single request through the guarded transport WITHOUT following
// redirects, so a check can read the first-hop Location header. It reuses the
// guarded client's Transport, so scope, rate limit, scan window, kill switch
// and the X-Scout-Scan signature all still apply — only redirect-following is
// suppressed. Returns the status code and response headers.
func hop(ctx context.Context, rawURL string) (status int, header http.Header, reqDump string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("User-Agent", "Scout/1 (+https://github.com/MUKE-coder/scout)")
	rt := core.HTTPClient(ctx).Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header, req.Method + " " + req.URL.RequestURI(), nil
}

// locationHostOf returns the hostname of a Location header value, resolved
// against base when the header is relative. "" when there is no usable
// Location.
func locationHostOf(base, location string) string {
	if location == "" {
		return ""
	}
	bu, err := url.Parse(base)
	if err != nil {
		return ""
	}
	lu, err := bu.Parse(location)
	if err != nil {
		return ""
	}
	return lu.Hostname()
}

// asset builds a URL asset for a finding, tagging the mutated parameter in
// Location via the caller.
func assetFor(t core.Target, rawURL string) core.Asset {
	u, err := url.Parse(rawURL)
	if err != nil {
		return core.Asset{Kind: core.AssetURL, Value: rawURL, Exposure: exposure(t), Criticality: t.Criticality}
	}
	return httpx.Asset(t, u)
}

func exposure(t core.Target) core.Exposure {
	if t.IsLocal() {
		return core.ExposureInternal
	}
	return core.ExposureInternet
}

// bodyString returns the response body as a string.
func bodyString(p *httpx.Page) string { return string(p.Body) }

// contains reports a case-sensitive substring (canaries are case-sensitive).
func contains(hay, needle string) bool { return strings.Contains(hay, needle) }

func sortedParamNames(q url.Values) []string {
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	// url.Values has no order; sort for determinism.
	sortStrings(names)
	return names
}

// sortStrings is a tiny insertion sort to avoid importing sort in a file that
// otherwise needs nothing else from it. (Deterministic output is required.)
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
