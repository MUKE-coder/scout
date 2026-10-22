// Package authz holds the authentication and access-control checks. Like
// dast, it is a SKELETON: metadata, modes, standards mapping and remediation
// are complete; the testing logic is a stub for you to implement. The same
// rules apply — every request through core.HTTPClient(ctx), test accounts
// only, non-destructive, honor the declared Mode().
//
// Access-control checks (IDOR, missing-auth, privilege escalation) need two
// configured test identities to compare what each may reach. Add that input
// to scout.Config when you implement them; do not use real user accounts.
//
// JWT checks inspect a token the operator supplies (passive analysis of its
// header/claims) — not a brute force. "Weak secret" cracking is out of scope
// here; detect alg:none, missing/!verified signature and missing expiry.
package authz

import (
	"context"

	"github.com/MUKE-coder/scout/core"
)

// Checks returns the access-control checks. Register the implemented ones via
// collectors/all.
func Checks() []core.Check {
	return []core.Check{
		JWT{}, IDOR{}, MissingAuth{}, CORS{}, MassAssignment{},
	}
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
	// TODO(you): given a token (from config or a login via test account),
	// decode header/claims and flag alg:none, missing signature verification,
	// or a missing/overlong exp. Attach RemediationJWT. Inspection only.
	return nil, nil
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
	// TODO(you): with two test accounts, request account A's object IDs as
	// account B and flag any that return B unauthorized data. Attach
	// RemediationIDOR.
	return nil, nil
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
	// TODO(you): request discovered/routed endpoints with no credentials and
	// flag those that return protected data instead of 401/403. With
	// scout.Mount, cross-check t.Routes for routes lacking auth middleware
	// (that part can run in passive mode — see the note below). Attach
	// RemediationMissingAuth.
	return nil, nil
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
	// TODO(you): send requests with an Origin header and flag reflecting an
	// arbitrary origin together with Access-Control-Allow-Credentials: true,
	// or a wildcard with credentials. Attach RemediationCORS. (Reading
	// response headers is safe mode.)
	return nil, nil
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
	// TODO(you): with a test account, submit an extra privileged field to an
	// update endpoint and verify (read-back) whether it was applied. Attach
	// RemediationMassAssignment. Non-destructive: revert or use a scratch
	// object.
	return nil, nil
}

var RemediationMassAssignment = core.Remediation{
	What:       "An endpoint binds request fields straight onto a model, including fields the user should not set.",
	Why:        "An attacker adds a field such as a role or account flag to escalate privileges or tamper with data.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Bind to an explicit allowlist DTO of editable fields; never bind untrusted input directly onto persistent models."}},
	Effort:     core.EffortM,
	References: []string{"https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"},
}
