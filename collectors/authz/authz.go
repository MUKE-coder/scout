// Package authz holds the authentication and access-control checks. Like
// dast, it is a SKELETON: metadata, modes, standards mapping and remediation
// are complete; the testing logic is a stub for you to implement. The same
// rules apply — every request through core.HTTPClient(ctx), test accounts
// only, non-destructive, honor the declared Mode().
//
// Access-control checks (IDOR, privilege escalation) need two configured test
// identities to compare what each may reach. That surface now exists
// (scout.WithTestIdentities / core.Target.Identities); IDOR uses it. Supply
// disposable test accounts only — never real user accounts.
//
// JWT checks inspect a token the operator supplies (passive analysis of its
// header/claims) — not a brute force. "Weak secret" cracking is out of scope
// here; detect alg:none, missing/!verified signature and missing expiry.
package authz

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

// init registers the IMPLEMENTED access-control checks. A blank import of this
// package (from collectors/all) activates them. IDOR is registered and runs
// only when test identities are configured. MassAssignment is still excluded:
// a correct probe is state-changing and needs a scratch object, which Scout
// cannot yet create safely — see its Run method.
func init() {
	for _, c := range implementedChecks() {
		core.Register(c)
	}
}

// Checks returns every access-control check, implemented or not, for metadata
// and template tests.
func Checks() []core.Check {
	return []core.Check{
		JWT{}, IDOR{}, MissingAuth{}, CORS{}, MassAssignment{},
	}
}

// implementedChecks returns only the checks with real probe logic, which are
// the ones registered and run. IDOR runs only when test identities are
// configured (see its Run); without them it reports nothing.
func implementedChecks() []core.Check {
	return []core.Check{JWT{}, MissingAuth{}, CORS{}, IDOR{}}
}

// --- JWT weaknesses (passive token inspection) -------------------------

type JWT struct{}

func (JWT) ID() string              { return "auth.jwt" }
func (JWT) Category() core.Category { return core.CategoryAuth }
func (JWT) Mode() core.Mode         { return core.ModePassive }
func (JWT) Description() string     { return "JWT uses alg:none, is unsigned, or has no expiry" }
func (JWT) OWASP() []string         { return []string{"A07:2021"} }
func (JWT) ASVS() []string          { return []string{"V3.5.3"} }

func (c JWT) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	// Harvest tokens observed on the base page and discovered endpoints.
	urls := []string{t.URL}
	urls = append(urls, res.Endpoints...)
	seenToken := map[string]bool{}
	var out []core.Finding
	for _, raw := range urls {
		if raw == "" {
			continue
		}
		page, gerr := httpx.Get(ctx, raw)
		if gerr != nil {
			continue
		}
		for _, tok := range tokensFromPage(page) {
			if seenToken[tok] {
				continue
			}
			seenToken[tok] = true
			hdr, claims, ok := parseJWT(tok)
			if !ok {
				continue
			}
			if f, bad := jwtWeakness(t, page, hdr, claims); bad {
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// jwtWeakness returns a finding when a token's header/claims are unsafe.
// Signature strength is out of scope (no cracking); we flag alg:none and a
// missing expiry, the two weaknesses provable by inspection alone.
func jwtWeakness(t core.Target, page *httpx.Page, hdr jwtHeader, claims jwtClaims) (core.Finding, bool) {
	alg := strings.ToLower(strings.TrimSpace(hdr.Alg))
	var problems []string
	if alg == "none" || alg == "" {
		problems = append(problems, "alg:none (unsigned)")
	}
	if claims.Exp == nil {
		problems = append(problems, "no exp claim (never expires)")
	}
	if len(problems) == 0 {
		return core.Finding{}, false
	}
	sev := core.SeverityMedium
	if alg == "none" || alg == "" {
		sev = core.SeverityHigh // forgeable
	}
	return core.Finding{
		Title:      "Weak JWT: " + strings.Join(problems, ", "),
		Category:   core.CategoryAuth,
		Severity:   sev,
		Confidence: core.ConfidenceConfirmed, // read straight from the token
		Asset:      urlAsset(t, page.URL.String()),
		Location:   "jwt",
		Evidence: core.Evidence{
			Matched:  "JWT header alg=" + hdr.Alg + "; " + strings.Join(problems, "; "),
			Notes:    "token inspected, not verified or stored",
			Redacted: true,
		},
		CWE:         []string{"CWE-347"},
		OWASP:       []string{"A07:2021"},
		Remediation: RemediationJWT,
	}, true
}

var RemediationJWT = core.Remediation{
	What:       "A JSON Web Token accepts an unsafe algorithm, is not signature-verified, or never expires.",
	Why:        "alg:none or unverified signatures let an attacker forge tokens and impersonate any user; tokens without expiry stay valid forever if stolen.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Pin the expected algorithm (reject 'none'), always verify the signature with the server key, set a short 'exp', and rotate signing keys."}},
	Effort:     core.EffortM,
	References: []string{"https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"},
}

// --- IDOR / broken object-level authorization --------------------------

type IDOR struct{}

func (IDOR) ID() string              { return "auth.idor" }
func (IDOR) Category() core.Category { return core.CategoryAuth }
func (IDOR) Mode() core.Mode         { return core.ModeActive }
func (IDOR) Description() string     { return "One user can reach another user's object (IDOR)" }
func (IDOR) OWASP() []string         { return []string{"A01:2021"} }
func (IDOR) ASVS() []string          { return []string{"V4.2.1"} }

func (c IDOR) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	// IDOR is proven by comparison: one identity owns a private resource; a
	// different identity must not be able to read it. This needs at least two
	// configured test identities (scout.WithTestIdentities), at least one of
	// which declares an owned resource. Without that config the check reports
	// nothing — it is not a silent no-op, it is "not configured".
	if t.URL == "" || len(t.Identities) < 2 {
		return nil, nil
	}

	var out []core.Finding
	reported := map[string]bool{}

	for _, owner := range t.Identities {
		for _, owned := range owner.Owns {
			target := resolveOwnedURL(t.URL, owned)
			if target == "" {
				continue
			}
			// Establish the ownership baseline: the owner must actually be able
			// to read its own resource. If not, we cannot prove anything.
			ownerPage, err := doWithHeaders(ctx, target, headerFrom(owner.Headers))
			if err != nil || !protectedStatusOK(ownerPage.Status) || len(ownerPage.Body) == 0 {
				continue
			}
			ownerFP := bodyFingerprint(ownerPage.Body)

			// Any other identity that receives the byte-identical object has
			// reached data it does not own: a confirmed IDOR. Requests are
			// read-only GETs; the owner's data is never included in evidence.
			for _, other := range t.Identities {
				if other.Name == owner.Name {
					continue
				}
				otherPage, err := doWithHeaders(ctx, target, headerFrom(other.Headers))
				if err != nil || !protectedStatusOK(otherPage.Status) || len(otherPage.Body) == 0 {
					continue
				}
				if bodyFingerprint(otherPage.Body) != ownerFP {
					continue // got its own/different object, or a generic page
				}
				key := other.Name + "->" + target
				if reported[key] {
					continue
				}
				reported[key] = true
				out = append(out, core.Finding{
					Title:      "IDOR: one user can read another user's object",
					Category:   core.CategoryAuth,
					Severity:   core.SeverityHigh,
					Confidence: core.ConfidenceConfirmed,
					Asset:      urlAsset(t, target),
					Location:   target,
					Evidence: core.Evidence{
						Request:  otherPage.Request,
						Matched:  "identity " + other.Name + " received the identical object owned by " + owner.Name,
						Notes:    "non-destructive GET; response bodies compared by hash, contents not stored",
						Redacted: true,
					},
					CWE:         []string{"CWE-639"},
					OWASP:       []string{"A01:2021"},
					Remediation: RemediationIDOR,
				})
			}
		}
	}
	return out, nil
}

var RemediationIDOR = core.Remediation{
	What:       "An object is served based on an ID in the request without checking the caller owns it.",
	Why:        "An attacker changes an ID in the URL or body to read or modify other users' data.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Enforce an ownership/role check on every object access, server-side; prefer unguessable IDs but never rely on them for authorization."}},
	Effort:     core.EffortM,
	References: []string{"https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
}

// --- Missing authentication on routes ----------------------------------

type MissingAuth struct{}

func (MissingAuth) ID() string              { return "auth.missing" }
func (MissingAuth) Category() core.Category { return core.CategoryAuth }
func (MissingAuth) Mode() core.Mode         { return core.ModeActive }
func (MissingAuth) Description() string {
	return "A sensitive route is reachable without authentication"
}
func (MissingAuth) OWASP() []string { return []string{"A01:2021"} }

func (c MissingAuth) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	var out []core.Finding
	reported := map[string]bool{}

	// 1. Route-table analysis (requires scout.Mount). A sensitive route whose
	// middleware chain contains no auth gate is a confirmed gap in the config,
	// independent of any request.
	for _, r := range t.Routes {
		if !looksSensitive(r.Path) || hasAuthMiddleware(r.Middleware) {
			continue
		}
		key := "route:" + strings.ToUpper(r.Method) + " " + r.Path
		if reported[key] {
			continue
		}
		reported[key] = true
		out = append(out, core.Finding{
			Title:       "Route has no auth middleware: " + strings.ToUpper(r.Method) + " " + r.Path,
			Category:    core.CategoryAuth,
			Severity:    core.SeverityHigh,
			Confidence:  core.ConfidenceConfirmed,
			Asset:       core.Asset{Kind: core.AssetRoute, Value: strings.ToUpper(r.Method) + " " + r.Path, Method: r.Method, Path: r.Path, Exposure: exposure(t), Criticality: t.Criticality},
			Location:    strings.ToUpper(r.Method) + " " + r.Path,
			Evidence:    core.Evidence{Matched: "middleware chain [" + strings.Join(r.Middleware, ", ") + "] contains no auth gate"},
			CWE:         []string{"CWE-306"},
			OWASP:       []string{"A01:2021"},
			Remediation: RemediationMissingAuth,
		})
	}

	// 2. Unauthenticated HTTP probe of discovered sensitive endpoints. A 2xx
	// with a body (not a login redirect or 401/403) is a likely gap. This is
	// "likely", not "confirmed": we cannot be certain the data is protected
	// without a comparison identity.
	res, err := discover(ctx, t)
	if err != nil {
		return out, err
	}
	if res != nil {
		for _, raw := range res.Endpoints {
			u, perr := url.Parse(raw)
			if perr != nil || !looksSensitive(u.EscapedPath()) {
				continue
			}
			key := "http:" + raw
			if reported[key] {
				continue
			}
			// Send with no credentials at all.
			page, gerr := doWithHeaders(ctx, raw, nil)
			if gerr != nil {
				continue
			}
			if !protectedStatusOK(page.Status) || len(page.Body) == 0 {
				continue // 401/403/redirect/empty → protected, good
			}
			reported[key] = true
			out = append(out, core.Finding{
				Title:       "Sensitive endpoint reachable without authentication",
				Category:    core.CategoryAuth,
				Severity:    core.SeverityMedium,
				Confidence:  core.ConfidenceLikely,
				Asset:       urlAsset(t, raw),
				Location:    u.EscapedPath(),
				Evidence:    core.Evidence{Request: page.Request, Notes: "unauthenticated GET returned 2xx with a body"},
				CWE:         []string{"CWE-306"},
				OWASP:       []string{"A01:2021"},
				Remediation: RemediationMissingAuth,
			})
		}
	}
	return out, nil
}

var RemediationMissingAuth = core.Remediation{
	What:       "An endpoint that exposes protected functionality or data has no authentication.",
	Why:        "Anyone can call it directly, bypassing the app's login entirely.",
	How:        []core.Fix{{Stack: "gin", Language: "go", Code: "// Apply auth middleware to the protected group, not per-handler ad hoc:\nprotected := r.Group(\"/api\", AuthRequired())\nprotected.GET(\"/account\", accountHandler)"}},
	Effort:     core.EffortM,
	References: []string{"https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
}

// --- CORS misconfiguration (safe) --------------------------------------

type CORS struct{}

func (CORS) ID() string              { return "auth.cors" }
func (CORS) Category() core.Category { return core.CategoryAuth }
func (CORS) Mode() core.Mode         { return core.ModeSafe }
func (CORS) Description() string     { return "CORS policy is dangerously permissive" }
func (CORS) OWASP() []string         { return []string{"A05:2021"} }

func (c CORS) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	const evilOrigin = "https://scout-cors-probe.example.com"
	var out []core.Finding
	reported := map[string]bool{}

	// Test the base URL and any discovered endpoints; one finding per origin
	// policy per URL.
	urls := []string{t.URL}
	urls = append(urls, res.Endpoints...)
	for _, raw := range urls {
		if raw == "" || reported[raw] {
			continue
		}
		h := http.Header{}
		h.Set("Origin", evilOrigin)
		page, gerr := doWithHeaders(ctx, raw, h)
		if gerr != nil {
			continue
		}
		acao := strings.TrimSpace(page.Header.Get("Access-Control-Allow-Origin"))
		acac := strings.EqualFold(strings.TrimSpace(page.Header.Get("Access-Control-Allow-Credentials")), "true")

		reflects := acao == evilOrigin
		wildcard := acao == "*"
		// The dangerous combinations: reflecting an arbitrary origin with
		// credentials, or (invalid but seen) wildcard with credentials.
		if !((reflects && acac) || (wildcard && acac)) {
			continue
		}
		reported[raw] = true
		detail := "reflects arbitrary Origin with credentials"
		if wildcard {
			detail = "wildcard Access-Control-Allow-Origin with credentials"
		}
		out = append(out, core.Finding{
			Title:      "Permissive CORS policy",
			Category:   core.CategoryAuth,
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceConfirmed,
			Asset:      urlAsset(t, raw),
			Evidence: core.Evidence{
				Request:  page.Request,
				Response: page.Response,
				Matched:  "Access-Control-Allow-Origin: " + acao + "; Access-Control-Allow-Credentials: true (" + detail + ")",
			},
			CWE:         []string{"CWE-942"},
			OWASP:       []string{"A05:2021"},
			Remediation: RemediationCORS,
		})
	}
	return out, nil
}

var RemediationCORS = core.Remediation{
	What:       "The server reflects arbitrary origins (or uses '*') while allowing credentials.",
	Why:        "A malicious site can make authenticated cross-origin requests and read the responses, stealing data on behalf of a logged-in user.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Allowlist specific trusted origins; never combine Access-Control-Allow-Credentials: true with a reflected or wildcard origin."}},
	Effort:     core.EffortS,
	References: []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"},
}

// --- Mass assignment ----------------------------------------------------

type MassAssignment struct{}

func (MassAssignment) ID() string              { return "auth.mass-assignment" }
func (MassAssignment) Category() core.Category { return core.CategoryAuth }
func (MassAssignment) Mode() core.Mode         { return core.ModeActive }
func (MassAssignment) Description() string {
	return "Extra fields (e.g. role) are accepted and persisted"
}
func (MassAssignment) OWASP() []string { return []string{"A08:2021"} }

func (c MassAssignment) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	// Deliberately not implemented yet, and intentionally NOT registered (see
	// implementedChecks). A correct probe submits an extra privileged field to
	// an update endpoint with a test account and reads back whether it stuck —
	// a state-changing request that needs a test identity and a scratch object
	// to stay non-destructive. Scout has neither config surface yet. Implement
	// once test accounts exist; until then this returns nothing.
	return nil, nil
}

var RemediationMassAssignment = core.Remediation{
	What:       "An endpoint binds request fields straight onto a model, including fields the user should not set.",
	Why:        "An attacker adds a field such as a role or account flag to escalate privileges or tamper with data.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Bind to an explicit allowlist DTO of editable fields; never bind untrusted input directly onto persistent models."}},
	Effort:     core.EffortM,
	References: []string{"https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"},
}
