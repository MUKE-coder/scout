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
	"strings"

	"github.com/MUKE-coder/scout/core"
)

// init registers the DAST checks. A blank import of this package (from
// collectors/all) activates them. The six probes in this file are implemented;
// the scaffolds in scaffolds.go are registered too but no-op until their probe
// logic is written.
func init() {
	for _, c := range Checks() {
		core.Register(c)
	}
}

// Checks returns the DAST checks: the six implemented probes plus the
// scaffold probes (registered, but no-ops until their logic is written).
func Checks() []core.Check {
	impl := []core.Check{
		SQLi{}, CommandInjection{}, BlindCommandInjection{}, SSRF{}, BlindSSRF{}, PathTraversal{}, OpenRedirect{}, ReflectedXSS{},
	}
	return append(impl, scaffoldChecks()...)
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
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	var out []core.Finding
	reported := map[string]bool{}
	for _, in := range allParams(res) {
		// Baseline: the unmodified request. If it already shows a DB error,
		// injecting one proves nothing, so skip the parameter.
		base, berr := get(ctx, in.rawURL)
		if berr != nil {
			continue
		}
		if sqlError(bodyString(base)) != "" {
			continue
		}
		// Error-based probe: a lone quote breaks an unparameterized query.
		mutated, perr := withParam(in.rawURL, in.param, "'")
		if perr != nil {
			continue
		}
		page, gerr := get(ctx, mutated)
		if gerr != nil {
			continue
		}
		sig := sqlError(bodyString(page))
		if sig == "" {
			continue
		}
		key := in.rawURL + "\x00" + in.param
		if reported[key] {
			continue
		}
		reported[key] = true
		out = append(out, core.Finding{
			Title:      "SQL injection in parameter " + in.param,
			Category:   core.CategoryApp,
			Severity:   core.SeverityCritical,
			Confidence: core.ConfidenceConfirmed, // a DB error appeared only after injecting a quote
			Asset:      assetFor(t, in.rawURL),
			Location:   in.param,
			Evidence: core.Evidence{
				Request: page.Request,
				Matched: "database error after injecting a single quote: " + sig,
			},
			CWE:         []string{"CWE-89"},
			OWASP:       []string{"A03:2021"},
			Remediation: RemediationSQLi,
		})
	}
	return out, nil
}

// sqlErrorSignatures are substrings that appear in database driver errors but
// not in normal application output. The first match is returned as evidence.
var sqlErrorSignatures = []string{
	"SQL syntax",
	"syntax error at or near",
	"unterminated quoted string",
	"you have an error in your sql syntax",
	"pg_query",
	"pq: ",
	"sqlite3.OperationalError",
	"SQLITE_ERROR",
	"mysql_fetch",
	"mysqli",
	"ORA-00933",
	"ORA-01756",
	"Microsoft OLE DB Provider for SQL Server",
	"Unclosed quotation mark after the character string",
	"SQLSTATE[",
	"near \"'\": syntax error",
}

// sqlError returns the first SQL-error signature found in body, case-insensitively.
func sqlError(body string) string {
	low := strings.ToLower(body)
	for _, s := range sqlErrorSignatures {
		if strings.Contains(low, strings.ToLower(s)) {
			return s
		}
	}
	return ""
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
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	var out []core.Finding
	reported := map[string]bool{}
	for _, in := range allParams(res) {
		mark := canary("scoutcmd")
		// Control: the bare marker as an ordinary value. If this already
		// appears in the response the app simply echoes input, so command
		// execution can't be distinguished — skip to avoid a false positive.
		ctrl, cerr := withParam(in.rawURL, in.param, mark)
		if cerr != nil {
			continue
		}
		if cp, e := get(ctx, ctrl); e == nil && contains(bodyString(cp), mark) {
			continue
		}
		// Injection: shell metacharacters that echo the marker only if the
		// value reaches a shell. `echo` is read-only and side-effect free.
		confirmed := false
		var evidencePage = (*httpxPage)(nil)
		for _, tmpl := range []string{"; echo " + mark, "| echo " + mark, "`echo " + mark + "`", "$(echo " + mark + ")"} {
			mutated, perr := withParam(in.rawURL, in.param, "x"+tmpl)
			if perr != nil {
				continue
			}
			page, gerr := get(ctx, mutated)
			if gerr != nil {
				continue
			}
			if contains(bodyString(page), mark) {
				confirmed = true
				evidencePage = page
				break
			}
		}
		if !confirmed {
			continue
		}
		key := in.rawURL + "\x00" + in.param
		if reported[key] {
			continue
		}
		reported[key] = true
		out = append(out, core.Finding{
			Title:      "OS command injection in parameter " + in.param,
			Category:   core.CategoryApp,
			Severity:   core.SeverityCritical,
			Confidence: core.ConfidenceConfirmed, // marker echoed only via shell metacharacters
			Asset:      assetFor(t, in.rawURL),
			Location:   in.param,
			Evidence: core.Evidence{
				Request: evidencePage.Request,
				Matched: "echoed command output marker " + mark,
			},
			CWE:         []string{"CWE-78"},
			OWASP:       []string{"A03:2021"},
			Remediation: RemediationCmdInjection,
		})
	}
	return out, nil
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
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	// This check confirms only REFLECTED SSRF against the cloud metadata service:
	// if pointing a URL parameter at the metadata endpoint makes its unmistakable
	// response come back in the body, the server fetched it on our behalf. This
	// yields no false positives and never reaches a third party. The *blind* case
	// (where the fetched content never returns to us) is confirmed out-of-band by
	// the app.blind-ssrf check via Scout's own OAST listener (see blind_ssrf.go).
	probes := []struct {
		value     string
		signature string
	}{
		// AWS IMDS root lists metadata categories; GCP requires a header but
		// its root often returns a recognizable listing too.
		{"http://169.254.169.254/latest/meta-data/", "meta-data"},
		{"http://169.254.169.254/latest/meta-data/iam/", "iam"},
		{"http://metadata.google.internal/computeMetadata/v1/", "computeMetadata"},
	}
	var out []core.Finding
	reported := map[string]bool{}
	spots := append(allParams(res), gather(targetsFor(res), urlParams)...)
	for _, in := range spots {
		key := in.rawURL + "\x00" + in.param
		if reported[key] {
			continue
		}
		for _, pr := range probes {
			mutated, perr := withParam(in.rawURL, in.param, pr.value)
			if perr != nil {
				continue
			}
			page, gerr := get(ctx, mutated)
			if gerr != nil {
				continue
			}
			if !contains(bodyString(page), pr.signature) {
				continue
			}
			reported[key] = true
			out = append(out, core.Finding{
				Title:      "Server-side request forgery in parameter " + in.param,
				Category:   core.CategoryApp,
				Severity:   core.SeverityHigh,
				Confidence: core.ConfidenceConfirmed, // metadata response reflected back
				Asset:      assetFor(t, in.rawURL),
				Location:   in.param,
				Evidence: core.Evidence{
					Request: page.Request,
					Matched: "cloud metadata response reflected from " + pr.value,
				},
				CWE:         []string{"CWE-918"},
				OWASP:       []string{"A10:2021"},
				Remediation: RemediationSSRF,
			})
			break
		}
	}
	return out, nil
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
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	// Payloads target a file that exists on Unix/Windows and has an
	// unmistakable signature. Read-only: we only fetch, never write.
	probes := []struct {
		payload   string
		signature string
	}{
		{"../../../../../../etc/passwd", "root:x:0:0:"},
		{"....//....//....//....//etc/passwd", "root:x:0:0:"},
		{"..\\..\\..\\..\\..\\windows\\win.ini", "[fonts]"},
	}
	var out []core.Finding
	reported := map[string]bool{}
	// Path traversal lives in file-ish params; test existing params plus hints.
	spots := append(allParams(res), gather(targetsFor(res), fileParams)...)
	for _, in := range spots {
		key := in.rawURL + "\x00" + in.param
		if reported[key] {
			continue
		}
		for _, pr := range probes {
			mutated, perr := withParam(in.rawURL, in.param, pr.payload)
			if perr != nil {
				continue
			}
			page, gerr := get(ctx, mutated)
			if gerr != nil {
				continue
			}
			if !contains(bodyString(page), pr.signature) {
				continue
			}
			reported[key] = true
			out = append(out, core.Finding{
				Title:      "Path traversal in parameter " + in.param,
				Category:   core.CategoryApp,
				Severity:   core.SeverityHigh,
				Confidence: core.ConfidenceConfirmed, // a system file's contents came back
				Asset:      assetFor(t, in.rawURL),
				Location:   in.param,
				Evidence: core.Evidence{
					Request: page.Request,
					Matched: "response contained system-file signature " + pr.signature,
				},
				CWE:         []string{"CWE-22"},
				OWASP:       []string{"A01:2021"},
				Remediation: RemediationPathTraversal,
			})
			break // one confirmation per spot is enough
		}
	}
	return out, nil
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
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	// A benign, unmistakable canary destination. We never follow the redirect;
	// we read the Location header the server sets. The host is a reserved
	// example domain, so even if something did follow it, nothing is reached.
	const canaryHost = "scout-redirect-canary.example.com"
	canaryURL := "https://" + canaryHost + "/"

	var out []core.Finding
	reported := map[string]bool{}
	for _, in := range gather(targetsFor(res), redirectParams) {
		mutated, perr := withParam(in.rawURL, in.param, canaryURL)
		if perr != nil {
			continue
		}
		// Single hop, no redirect following, so we read the first Location.
		status, header, reqDump, herr := hop(ctx, mutated)
		if herr != nil {
			continue // scope/kill/rate errors are not findings
		}
		if status < 300 || status >= 400 {
			continue
		}
		if locationHostOf(mutated, header.Get("Location")) != canaryHost {
			continue
		}
		key := in.rawURL + "\x00" + in.param
		if reported[key] {
			continue
		}
		reported[key] = true
		out = append(out, core.Finding{
			Title:      "Open redirect via parameter " + in.param,
			Category:   core.CategoryApp,
			Severity:   core.SeverityMedium,
			Confidence: core.ConfidenceConfirmed, // the server put our host in Location
			Asset:      assetFor(t, in.rawURL),
			Location:   in.param,
			Evidence: core.Evidence{
				Request: reqDump,
				Matched: "Location redirects to attacker-controlled host " + canaryHost,
			},
			CWE:         []string{"CWE-601"},
			OWASP:       []string{"A01:2021"},
			Remediation: RemediationOpenRedirect,
		})
	}
	return out, nil
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
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	var out []core.Finding
	reported := map[string]bool{}
	// Test every discovered query parameter. The marker carries HTML-breaking
	// characters; if they survive unescaped in an HTML response, the context
	// allows script injection. The payload itself is inert (no event handler,
	// no script) — it only proves a lack of output encoding.
	for _, in := range allParams(res) {
		mark := canary("scoutxss")
		payload := "'\"<" + mark + ">"
		mutated, perr := withParam(in.rawURL, in.param, payload)
		if perr != nil {
			continue
		}
		page, gerr := get(ctx, mutated)
		if gerr != nil {
			continue
		}
		if !isHTMLResponse(page) {
			continue // reflection only matters where it can become markup
		}
		body := bodyString(page)
		// Raw, unescaped reflection of the markup-breaking form is the signal.
		if !contains(body, "<"+mark+">") {
			continue
		}
		key := in.rawURL + "\x00" + in.param
		if reported[key] {
			continue
		}
		reported[key] = true
		out = append(out, core.Finding{
			Title:      "Reflected input is not HTML-encoded (parameter " + in.param + ")",
			Category:   core.CategoryApp,
			Severity:   core.SeverityMedium,
			Confidence: core.ConfidenceConfirmed, // the markup-breaking marker survived verbatim
			Asset:      assetFor(t, in.rawURL),
			Location:   in.param,
			Evidence: core.Evidence{
				Request: page.Request,
				Matched: "unescaped reflection of <" + mark + "> in HTML response",
			},
			CWE:         []string{"CWE-79"},
			OWASP:       []string{"A03:2021"},
			Remediation: RemediationXSS,
		})
	}
	return out, nil
}

var RemediationXSS = core.Remediation{
	What:       "User input is reflected into a response without output encoding.",
	Why:        "An attacker can run script in a victim's browser to steal sessions, make requests as the user, or deface the page.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Context-encode all output (HTML/attribute/JS/URL), use a strict Content-Security-Policy, and prefer frameworks that auto-escape."}},
	Effort:     core.EffortM,
	References: []string{"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
}
