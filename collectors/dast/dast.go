// Package dast holds the active application-testing checks (injection and
// related classes). It is a SKELETON: the check metadata, modes, standards
// mapping and remediation are complete, but the actual input-testing logic
// is left as a stub for you to implement — Scout does not ship attack
// payloads.
//
// To finish a check, implement its probe method where marked `TODO(you)`.
// Rules your implementation MUST follow:
//
//   - Send every request through core.HTTPClient(ctx) — never a bare client.
//     That keeps the request inside scope, under the rate limit and scan
//     window, honoring the kill switch, and signed with X-Scout-Scan.
//   - Respect the declared Mode(). The engine only runs a check when the
//     environment's cap allows it; active checks additionally require
//     ownership verification on non-local hosts (both already enforced).
//   - Use only configured test accounts and non-destructive requests.
//   - Discover targets with crawl.Crawl(ctx, t) (pages, forms, endpoints).
//   - Return a core.Finding per confirmed issue, with evidence; set
//     Confidence honestly (confirmed only when proven).
//
// Until the stubs are implemented each Run returns no findings. Wire the
// package into collectors/all only once a check is real.
package dast

import (
	"context"

	"github.com/MUKE-coder/scout/core"
)

// Checks returns the DAST checks. They are NOT registered here; add the ones
// you implement to collectors/all so the default build only exposes working
// checks.
func Checks() []core.Check {
	return []core.Check{
		SQLi{}, CommandInjection{}, SSRF{}, PathTraversal{}, OpenRedirect{}, ReflectedXSS{},
	}
}

// --- SQL injection ------------------------------------------------------

type SQLi struct{}

func (SQLi) ID() string              { return "app.sqli" }
func (SQLi) Category() core.Category { return core.CategoryApp }
func (SQLi) Mode() core.Mode         { return core.ModeActive }
func (SQLi) Description() string     { return "A parameter is vulnerable to SQL injection" }
func (SQLi) OWASP() []string         { return []string{"A03:2021"} }
func (SQLi) ASVS() []string          { return []string{"V5.3.4"} }

func (c SQLi) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	// TODO(you): for each discovered form field / query parameter, test for
	// SQL injection and return a finding when confirmed. Use RemediationSQLi
	// for the fix guidance. Until then, no findings.
	return nil, nil
}

// RemediationSQLi is the fix guidance to attach to app.sqli findings.
var RemediationSQLi = core.Remediation{
	What: "Untrusted input reaches a SQL query in a way that lets it change the query's structure.",
	Why:  "An attacker can read, modify or destroy data, bypass authentication, or in some setups run commands on the database host.",
	How: []core.Fix{
		{Stack: "gin", Language: "go", Code: "// Use parameterized queries / prepared statements, never string concatenation.\ndb.Query(\"SELECT * FROM users WHERE id = ?\", id)\n// With an ORM (GORM): db.Where(\"id = ?\", id).First(&u)"},
		{Stack: "generic", Language: "text", Code: "Use parameterized queries everywhere, validate/allowlist input types, and grant the DB account least privilege."},
	},
	Effort:     core.EffortM,
	References: []string{"https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
}

// --- OS command injection ----------------------------------------------

type CommandInjection struct{}

func (CommandInjection) ID() string              { return "app.cmd-injection" }
func (CommandInjection) Category() core.Category { return core.CategoryApp }
func (CommandInjection) Mode() core.Mode         { return core.ModeActive }
func (CommandInjection) Description() string     { return "A parameter reaches an OS command" }
func (CommandInjection) OWASP() []string         { return []string{"A03:2021"} }
func (CommandInjection) ASVS() []string          { return []string{"V5.3.8"} }

func (c CommandInjection) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	// TODO(you): test inputs that may reach an OS command; attach RemediationCmdInjection.
	return nil, nil
}

var RemediationCmdInjection = core.Remediation{
	What:       "Untrusted input is passed to an operating-system command.",
	Why:        "An attacker who can influence a shell command can run arbitrary commands on the server.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Avoid shelling out; call APIs directly. If you must exec, pass arguments as a list (never a shell string), and allowlist values."}},
	Effort:     core.EffortM,
	References: []string{"https://owasp.org/www-community/attacks/Command_Injection"},
}

// --- SSRF ---------------------------------------------------------------

type SSRF struct{}

func (SSRF) ID() string              { return "app.ssrf" }
func (SSRF) Category() core.Category { return core.CategoryApp }
func (SSRF) Mode() core.Mode         { return core.ModeActive }
func (SSRF) Description() string     { return "A parameter causes server-side requests (SSRF)" }
func (SSRF) OWASP() []string         { return []string{"A10:2021"} }
func (SSRF) ASVS() []string          { return []string{"V5.2.6"} }

func (c SSRF) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	// TODO(you): test URL/host parameters for server-side request forgery;
	// attach RemediationSSRF. Prefer an out-of-band canary you control.
	return nil, nil
}

var RemediationSSRF = core.Remediation{
	What:       "The server fetches a URL supplied by the user without restriction.",
	Why:        "An attacker can make the server reach internal services and cloud metadata endpoints it should not, leaking credentials or pivoting inside the network.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Allowlist destination hosts/schemes, resolve and block private/link-local ranges, disable redirects, and require egress through a proxy."}},
	Effort:     core.EffortL,
	References: []string{"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"},
}

// --- Path traversal -----------------------------------------------------

type PathTraversal struct{}

func (PathTraversal) ID() string              { return "app.path-traversal" }
func (PathTraversal) Category() core.Category { return core.CategoryApp }
func (PathTraversal) Mode() core.Mode         { return core.ModeActive }
func (PathTraversal) Description() string     { return "A parameter allows path traversal" }
func (PathTraversal) OWASP() []string         { return []string{"A01:2021"} }
func (PathTraversal) ASVS() []string          { return []string{"V12.3.1"} }

func (c PathTraversal) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	// TODO(you): test file/path parameters for traversal; attach RemediationPathTraversal.
	return nil, nil
}

var RemediationPathTraversal = core.Remediation{
	What:       "A file path is built from user input without containment.",
	Why:        "An attacker can read or write files outside the intended directory, such as configuration or secrets.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Resolve the final path and verify it stays within an allowed base directory; reject '..' and absolute paths; prefer opaque IDs over filenames."}},
	Effort:     core.EffortM,
	References: []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
}

// --- Open redirect (safe mode) -----------------------------------------

type OpenRedirect struct{}

func (OpenRedirect) ID() string              { return "app.open-redirect" }
func (OpenRedirect) Category() core.Category { return core.CategoryApp }
func (OpenRedirect) Mode() core.Mode         { return core.ModeSafe }
func (OpenRedirect) Description() string {
	return "A redirect parameter allows an arbitrary destination"
}
func (OpenRedirect) OWASP() []string { return []string{"A01:2021"} }

func (c OpenRedirect) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	// TODO(you): test redirect parameters (safe: a GET with a benign external
	// canary host and no automatic following); attach RemediationOpenRedirect.
	return nil, nil
}

var RemediationOpenRedirect = core.Remediation{
	What:       "A redirect target is taken from user input without validation.",
	Why:        "Attackers use open redirects for convincing phishing and to bypass allowlists in OAuth and SSO flows.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Redirect only to an allowlist of paths/hosts, or map a server-side key to the destination; never redirect to a raw user-supplied URL."}},
	Effort:     core.EffortS,
	References: []string{"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
}

// --- Reflected XSS (safe-mode canary) ----------------------------------

type ReflectedXSS struct{}

func (ReflectedXSS) ID() string              { return "app.reflected-xss" }
func (ReflectedXSS) Category() core.Category { return core.CategoryApp }
func (ReflectedXSS) Mode() core.Mode         { return core.ModeSafe }
func (ReflectedXSS) Description() string     { return "User input is reflected unescaped (possible XSS)" }
func (ReflectedXSS) OWASP() []string         { return []string{"A03:2021"} }
func (ReflectedXSS) ASVS() []string          { return []string{"V5.3.3"} }

func (c ReflectedXSS) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	// TODO(you): send a harmless unique canary string in parameters and flag
	// when it is reflected without contextual encoding. Attach RemediationXSS.
	return nil, nil
}

var RemediationXSS = core.Remediation{
	What:       "User input is reflected into a response without output encoding.",
	Why:        "An attacker can run script in a victim's browser to steal sessions, make requests as the user, or deface the page.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Context-encode all output (HTML/attribute/JS/URL), use a strict Content-Security-Policy, and prefer frameworks that auto-escape."}},
	Effort:     core.EffortM,
	References: []string{"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
}
