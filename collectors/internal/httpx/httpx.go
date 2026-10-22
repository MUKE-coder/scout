// Package httpx is the shared HTTP helper for collectors. Every request goes
// through the scan's guarded client (core.HTTPClient), and responses are
// memoized per scan so checks that read the same page share one request.
package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/MUKE-coder/scout/core"
)

// MaxBody caps how much of a response body is read.
const MaxBody = 1 << 20

// maxEvidenceBody caps the body excerpt kept in evidence.
const maxEvidenceBody = 2048

// Page is a fetched response.
type Page struct {
	URL      *url.URL // final URL after redirects
	Status   int
	Header   http.Header
	Cookies  []*http.Cookie
	Body     []byte
	Request  string // evidence: request line + headers
	Response string // evidence: status, headers, truncated body
}

// Get fetches rawURL once per scan.
func Get(ctx context.Context, rawURL string) (*Page, error) {
	return core.Memo(ctx, "httpx.get:"+rawURL, func() (*Page, error) {
		return Do(ctx, http.MethodGet, rawURL, nil)
	})
}

// Do sends one request through the guarded client without memoizing.
func Do(ctx context.Context, method, rawURL string, header http.Header) (*Page, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Scout/1 (+https://github.com/MUKE-coder/scout)")
	for k, vs := range header {
		// Go ignores a "Host" header value; it must be set on req.Host. Honor
		// it so checks (e.g. host-header injection) can override the Host.
		if http.CanonicalHeaderKey(k) == "Host" {
			if len(vs) > 0 {
				req.Host = vs[0]
			}
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := core.HTTPClient(ctx).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return nil, err
	}
	return &Page{
		URL:      resp.Request.URL,
		Status:   resp.StatusCode,
		Header:   resp.Header,
		Cookies:  resp.Cookies(),
		Body:     body,
		Request:  dumpRequest(resp.Request),
		Response: dumpResponse(resp, body),
	}, nil
}

func dumpRequest(r *http.Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, r.URL.RequestURI(), r.URL.Host)
	writeHeaders(&b, r.Header)
	return b.String()
}

func dumpResponse(resp *http.Response, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", resp.Status)
	writeHeaders(&b, resp.Header)
	b.WriteString("\r\n")
	if len(body) > maxEvidenceBody {
		b.Write(body[:maxEvidenceBody])
		fmt.Fprintf(&b, "\n... (%d bytes truncated)", len(body)-maxEvidenceBody)
	} else {
		b.Write(body)
	}
	return b.String()
}

func writeHeaders(b *strings.Builder, h http.Header) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(b, "%s: %s\r\n", k, v)
		}
	}
}

// Asset describes a URL on the target as a finding asset.
func Asset(t core.Target, u *url.URL) core.Asset {
	exposure := core.ExposureInternet
	if t.IsLocal() {
		exposure = core.ExposureInternal
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return core.Asset{
		Kind:        core.AssetURL,
		Value:       u.Scheme + "://" + u.Host + path,
		Host:        u.Hostname(),
		Path:        path,
		Exposure:    exposure,
		Criticality: t.Criticality,
	}
}

// Resolve joins a path onto the target's base URL.
func Resolve(t core.Target, path string) (*url.URL, error) {
	base, err := url.Parse(t.URL)
	if err != nil {
		return nil, err
	}
	return base.Parse(path)
}
