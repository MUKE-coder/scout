package dast

// This file holds SCAFFOLD checks: their metadata, modes, standards mapping
// and remediation are complete and they are registered (so they appear in the
// catalog and run in active scans), but their probe logic is a stub you fill
// in — Scout does not ship attack payloads. Each Run discovers targets and
// then returns no findings until you implement the marked `TODO(you)` block.
//
// The same rules as the implemented probes apply (see dast.go): every request
// through core.HTTPClient(ctx), honor the declared Mode(), test accounts only,
// non-destructive, confirm honestly. Discover with discover(ctx, t) and reuse
// the helpers in probe.go (allParams, withParam, get, canary, contains, ...).
//
// When a probe is implemented, delete its scaffold note and move on; nothing
// else needs to change — it is already in Checks() and registered.

import (
	"context"

	"github.com/MUKE-coder/scout/core"
)

// scaffoldChecks are the registered-but-unimplemented active probes. They are
// appended to Checks() in dast.go, so the single init there registers them.
func scaffoldChecks() []core.Check {
	return []core.Check{SSTI{}, XXE{}, FileUpload{}, BusinessLogic{}}
}

// --- Server-Side Template Injection ------------------------------------

type SSTI struct{}

func (SSTI) ID() string              { return "app.ssti" }
func (SSTI) Category() core.Category { return core.CategoryApp }
func (SSTI) Mode() core.Mode         { return core.ModeActive }
func (SSTI) Description() string     { return "A parameter is evaluated by a server-side template engine" }
func (SSTI) OWASP() []string         { return []string{"A03:2021"} }
func (SSTI) ASVS() []string          { return []string{"V5.2.5"} }

func (c SSTI) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	// TODO(you): implement SSTI probing. Suggested approach:
	//   - For each spot in allParams(res), send a benign arithmetic marker in
	//     the common template syntaxes ({{N*M}}, ${N*M}, #{N*M}, <%= N*M %>)
	//     using two random factors from canary-derived numbers.
	//   - First send the literal marker as a control to rule out plain echo.
	//   - Confirm ONLY when the response contains the computed PRODUCT and not
	//     the literal expression — that proves server-side evaluation.
	//   - No destructive payloads: arithmetic only; never object/exec gadgets.
	// Confidence: Confirmed when the arithmetic is evaluated. CWE-1336 / A03.
	return nil, nil
}

var RemediationSSTI = core.Remediation{
	What: "Untrusted input is rendered by a server-side template engine, so it is evaluated as template code.",
	Why:  "An attacker can read server data and, in many engines, achieve remote code execution through template expressions.",
	How: []core.Fix{
		{Stack: "generic", Language: "text", Code: "Never build templates from user input. Pass user data as rendering context/variables to a pre-defined template, and use a sandboxed/logic-less engine where possible."},
	},
	Effort:     core.EffortM,
	References: []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"},
}

// --- XML External Entity (XXE) -----------------------------------------

type XXE struct{}

func (XXE) ID() string              { return "app.xxe" }
func (XXE) Category() core.Category { return core.CategoryApp }
func (XXE) Mode() core.Mode         { return core.ModeActive }
func (XXE) Description() string     { return "An XML parser resolves external entities (XXE)" }
func (XXE) OWASP() []string         { return []string{"A05:2021"} }
func (XXE) ASVS() []string          { return []string{"V5.5.2"} }

func (c XXE) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	// TODO(you): implement XXE probing. Suggested approach:
	//   - Target endpoints that accept XML (Content-Type application/xml or
	//     text/xml; discover from forms/endpoints and a probe POST).
	//   - In-band confirmation: define a benign internal DOCTYPE entity and
	//     reference it in a field, then check the response reflects the
	//     entity's expanded value. Prefer internal entities first; use a file
	//     entity (e.g. a harmless, always-present path) only with explicit
	//     opt-in, and NEVER target sensitive files or external URLs by default.
	//   - Blind XXE (out-of-band) needs a collaborator listener Scout does not
	//     have yet — skip it until that exists, like SSRF does.
	// Confidence: Confirmed on reflected entity expansion. CWE-611 / A05.
	return nil, nil
}

var RemediationXXE = core.Remediation{
	What: "An XML parser is configured to resolve external entities and DTDs from untrusted documents.",
	Why:  "An attacker can read local files, perform server-side requests (SSRF), or cause denial of service through entity expansion.",
	How: []core.Fix{
		{Stack: "generic", Language: "text", Code: "Disable DTDs and external entity resolution in the XML parser (the secure default in most modern libraries), or use a data format without entities (JSON) where possible."},
	},
	Effort:     core.EffortM,
	References: []string{"https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"},
}

// --- Unrestricted file upload ------------------------------------------

type FileUpload struct{}

func (FileUpload) ID() string              { return "app.file-upload" }
func (FileUpload) Category() core.Category { return core.CategoryApp }
func (FileUpload) Mode() core.Mode         { return core.ModeActive }
func (FileUpload) Description() string     { return "An upload endpoint accepts dangerous file types" }
func (FileUpload) OWASP() []string         { return []string{"A04:2021"} }
func (FileUpload) ASVS() []string          { return []string{"V12.2.1"} }

func (c FileUpload) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	// TODO(you): implement upload probing. This is STATE-CHANGING, so it needs
	// a configured test identity and a non-destructive guarantee. Suggested
	// approach:
	//   - Find multipart upload endpoints (forms with enctype multipart, or
	//     discovered /upload-like routes).
	//   - Upload a benign file with a disallowed extension/content-type (e.g. a
	//     harmless text payload named probe.<ext>, NOT executable code) and
	//     check whether the server accepts it and, ideally, serves it back with
	//     a dangerous content-type. Never upload a real webshell or payload.
	//   - Clean up afterward if the API allows it.
	// Confidence: Confirmed when a disallowed type is stored and reachable.
	// CWE-434 / A04.
	return nil, nil
}

var RemediationFileUpload = core.Remediation{
	What: "An upload endpoint does not restrict file type, content, size or storage location.",
	Why:  "An attacker can upload executable or malicious content and, if it is served or executed, take over the server or attack other users.",
	How: []core.Fix{
		{Stack: "generic", Language: "text", Code: "Allowlist content types and extensions, validate the actual content, store uploads outside the web root (or on object storage) with randomized names, serve them with a safe content-type and Content-Disposition, and cap size."},
	},
	Effort:     core.EffortM,
	References: []string{"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"},
}

// --- Business-logic abuse ----------------------------------------------

type BusinessLogic struct{}

func (BusinessLogic) ID() string              { return "app.business-logic" }
func (BusinessLogic) Category() core.Category { return core.CategoryApp }
func (BusinessLogic) Mode() core.Mode         { return core.ModeActive }
func (BusinessLogic) Description() string {
	return "A workflow accepts values that violate business rules (e.g. negative quantity)"
}
func (BusinessLogic) OWASP() []string { return []string{"A04:2021"} }
func (BusinessLogic) ASVS() []string  { return []string{"V11.1.2"} }

func (c BusinessLogic) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	// TODO(you): implement business-logic probing. This is STATE-CHANGING and
	// domain-specific, so it needs a configured test identity and a scratch
	// object. Suggested approach:
	//   - For a known workflow (e.g. checkout/transfer), submit values that
	//     should be rejected — negative quantity, negative amount, quantities
	//     that overflow, prices from the client — with a test account against a
	//     scratch cart/order, and check whether the server accepts them.
	//   - Keep it non-destructive: never complete a real purchase or transfer;
	//     stop at the first state that proves the rule is not enforced.
	// Confidence: Confirmed when an invalid value is accepted. CWE-840 / A04.
	return nil, nil
}

var RemediationBusinessLogic = core.Remediation{
	What: "A business workflow trusts client-supplied values instead of enforcing its own rules.",
	Why:  "An attacker manipulates quantities, prices or amounts to get free goods, negative charges or other unintended outcomes.",
	How: []core.Fix{
		{Stack: "generic", Language: "text", Code: "Enforce every invariant server-side (ranges, ownership, totals computed from trusted data), never trust client-sent prices or totals, and add tests for the abuse cases."},
	},
	Effort:     core.EffortL,
	References: []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README"},
}
