package authz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

// jwtHeader and jwtClaims are the parts of a JWT this collector inspects.
// Only fields used by the checks are modeled.
type jwtHeader struct {
	Alg string `json:"alg"`
}

type jwtClaims struct {
	// Exp is a pointer so a missing "exp" (never expires) is distinguishable
	// from exp=0. Its numeric value is not used, only its presence.
	Exp *float64 `json:"exp"`
}

var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)

// tokensFromPage harvests JWT-looking strings from a response's cookies,
// Authorization header and body. Detection only — tokens are never stored.
func tokensFromPage(p *httpx.Page) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		for _, m := range jwtRe.FindAllString(s, -1) {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	for _, c := range p.Cookies {
		add(c.Value)
	}
	add(p.Header.Get("Authorization"))
	add(string(p.Body))
	return out
}

// parseJWT decodes a token's header and claims. ok is false for anything that
// is not a well-formed three-part JWT; the signature is never verified.
func parseJWT(tok string) (hdr jwtHeader, claims jwtClaims, ok bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return jwtHeader{}, jwtClaims{}, false
	}
	if !decodeSegment(parts[0], &hdr) || !decodeSegment(parts[1], &claims) {
		return jwtHeader{}, jwtClaims{}, false
	}
	return hdr, claims, true
}

func decodeSegment(seg string, v any) bool {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		if b, err = base64.URLEncoding.DecodeString(seg); err != nil {
			return false
		}
	}
	return json.Unmarshal(b, v) == nil
}

// urlAsset builds a finding asset from a raw URL for the given target.
func urlAsset(t core.Target, raw string) core.Asset {
	u, err := url.Parse(raw)
	if err != nil {
		return core.Asset{Kind: core.AssetURL, Value: raw, Exposure: exposure(t), Criticality: t.Criticality}
	}
	return httpx.Asset(t, u)
}

// doWithHeaders issues a guarded GET with optional extra headers.
func doWithHeaders(ctx context.Context, rawURL string, h http.Header) (*httpx.Page, error) {
	return httpx.Do(ctx, http.MethodGet, rawURL, h)
}

// protectedStatusOK reports whether a status looks like it returned data
// (2xx) rather than an auth challenge or redirect.
func protectedStatusOK(status int) bool { return status >= 200 && status <= 299 }

// sensitiveWords flag a path that probably needs authentication.
var sensitiveWords = []string{
	"admin", "account", "accounts", "user", "users", "dashboard", "settings",
	"billing", "payment", "invoice", "profile", "/api", "api/", "internal",
	"manage", "config", "secret", "token", "order", "orders", "customer",
}

// looksSensitive is a heuristic: does this path probably expose protected
// functionality or data?
func looksSensitive(path string) bool {
	p := strings.ToLower(path)
	for _, w := range sensitiveWords {
		if strings.Contains(p, w) {
			return true
		}
	}
	return false
}

// authWords name middleware that gates access.
var authWords = []string{"auth", "jwt", "session", "login", "token", "require", "bearer", "oidc", "oauth", "identity", "protect", "guard", "authz", "rbac"}

// hasAuthMiddleware reports whether a middleware chain contains an auth gate.
func hasAuthMiddleware(mw []string) bool {
	for _, m := range mw {
		lm := strings.ToLower(m)
		for _, w := range authWords {
			if strings.Contains(lm, w) {
				return true
			}
		}
	}
	return false
}
