// Package exposure checks for sensitive files and endpoints that should never
// be reachable: dotfiles, VCS metadata, API docs, metrics, backups, directory
// listings and admin dashboards. These checks are "safe" mode — they request a
// fixed list of well-known paths with GET only and send no attack payloads —
// but they do touch paths beyond the home page, so they are not passive.
//
// To avoid false positives on single-page apps that answer 200 for everything,
// each check validates a content signature, not just the status code.
package exposure

import (
	"context"
	"net/http"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

func init() {
	core.Register(DotEnv{})
	core.Register(Git{})
	core.Register(Swagger{})
	core.Register(Metrics{})
	core.Register(BackupFiles{})
	core.Register(DirListing{})
	core.Register(Dashboards{})
}

// fetch requests a path on the target through the guarded client. A repo-only
// target (no URL) yields (nil, false, nil).
func fetch(ctx context.Context, t core.Target, path string) (*httpx.Page, bool, error) {
	if t.URL == "" {
		return nil, false, nil
	}
	u, err := httpx.Resolve(t, path)
	if err != nil {
		return nil, false, nil // a bad path is a bug in the check list, not a target error
	}
	p, err := httpx.Do(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, false, err
	}
	return p, true, nil
}

// reachable reports whether a response looks like a real hit (2xx) rather than
// a redirect-to-login or a blanket SPA 404-as-200. The caller still checks a
// content signature.
func reachable(p *httpx.Page) bool {
	return p.Status >= 200 && p.Status < 300
}

func bodyText(p *httpx.Page) string { return string(p.Body) }

func contentType(p *httpx.Page) string {
	return strings.ToLower(p.Header.Get("Content-Type"))
}

// looksHTML reports whether the response is an HTML page, which for a raw-file
// path (.env, .git/config) means we hit an app route or error page, not the file.
func looksHTML(p *httpx.Page) bool {
	if strings.Contains(contentType(p), "text/html") {
		return true
	}
	head := strings.ToLower(strings.TrimSpace(bodyText(p)))
	return strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html")
}

// DotEnv flags a reachable .env file containing environment-variable assignments.
type DotEnv struct{}

func (DotEnv) ID() string              { return "exposure.dotenv" }
func (DotEnv) Category() core.Category { return core.CategoryExposure }
func (DotEnv) Mode() core.Mode         { return core.ModeSafe }
func (DotEnv) Description() string     { return "A .env file is publicly reachable" }
func (DotEnv) OWASP() []string         { return []string{"A05:2021"} }
func (DotEnv) ASVS() []string          { return []string{"V14.3.2"} }

func (DotEnv) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := fetch(ctx, t, "/.env")
	if err != nil || !ok {
		return nil, err
	}
	if !reachable(p) || looksHTML(p) || !looksLikeDotenv(bodyText(p)) {
		return nil, nil
	}
	secret := mentionsSecret(bodyText(p))
	sev := core.SeverityHigh
	tags := []string{}
	if secret {
		sev = core.SeverityCritical
		tags = append(tags, core.TagExposedSecret)
	}
	return []core.Finding{{
		Title:      ".env file is publicly accessible",
		Category:   core.CategoryExposure,
		Severity:   sev,
		Confidence: core.ConfidenceConfirmed,
		Asset:      httpx.Asset(t, p.URL),
		Evidence:   core.Evidence{Request: p.Request, Response: redactedResponse(p), Redacted: true},
		CWE:        []string{"CWE-538"},
		OWASP:      []string{"A05:2021"},
		Tags:       tags,
		Remediation: core.Remediation{
			What:   "The application's .env file can be downloaded over HTTP.",
			Why:    "Environment files hold database passwords, API keys and signing secrets. A single request hands an attacker the keys to the whole system.",
			How:    denyDotfilesFix(),
			Effort: core.EffortS,
			References: []string{
				"https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
			},
		},
	}}, nil
}

func looksLikeDotenv(body string) bool {
	lines := strings.Split(body, "\n")
	hits := 0
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, _, ok := strings.Cut(ln, "=")
		if ok && k != "" && !strings.ContainsAny(k, " <>\"") {
			hits++
		}
	}
	return hits >= 2
}

// mentionsSecret reports whether text names a credential-ish key, marking a
// leaked secret.
func mentionsSecret(text string) bool {
	l := strings.ToLower(text)
	for _, k := range []string{"secret", "password", "passwd", "api_key", "apikey", "token", "private_key", "aws_", "database_url", "db_pass"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

func denyDotfilesFix() []core.Fix {
	return []core.Fix{
		{Stack: "nginx", Language: "nginx", Code: `location ~ /\. { deny all; return 404; }`},
		{Stack: "caddy", Language: "caddy", Code: `@dotfiles path /.*
respond @dotfiles 404`},
		{Stack: "generic", Language: "text", Code: "Keep secrets out of the web root entirely, and block dotfiles at the reverse proxy."},
	}
}

// Git flags an exposed .git directory (recoverable source + history).
type Git struct{}

func (Git) ID() string              { return "exposure.git" }
func (Git) Category() core.Category { return core.CategoryExposure }
func (Git) Mode() core.Mode         { return core.ModeSafe }
func (Git) Description() string     { return "A .git directory is publicly reachable" }
func (Git) OWASP() []string         { return []string{"A05:2021"} }
func (Git) ASVS() []string          { return []string{"V14.3.2"} }

func (Git) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := fetch(ctx, t, "/.git/config")
	if err != nil || !ok {
		return nil, err
	}
	if !reachable(p) || looksHTML(p) || !strings.Contains(bodyText(p), "[core]") {
		return nil, nil
	}
	return []core.Finding{{
		Title:      ".git directory is publicly accessible",
		Category:   core.CategoryExposure,
		Severity:   core.SeverityHigh,
		Confidence: core.ConfidenceConfirmed,
		Asset:      httpx.Asset(t, p.URL),
		Evidence:   core.Evidence{Request: p.Request, Response: p.Response},
		CWE:        []string{"CWE-527"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What:   "The .git/config file is reachable, so the whole repository and its history can be reconstructed.",
			Why:    "Attackers download the .git tree to recover source code, hardcoded secrets, and removed-but-committed credentials.",
			How:    denyDotfilesFix(),
			Effort: core.EffortS,
			References: []string{
				"https://owasp.org/www-project-web-security-testing-guide/",
			},
		},
	}}, nil
}

// Swagger flags exposed, unauthenticated API documentation.
type Swagger struct{}

func (Swagger) ID() string              { return "exposure.swagger" }
func (Swagger) Category() core.Category { return core.CategoryExposure }
func (Swagger) Mode() core.Mode         { return core.ModeSafe }
func (Swagger) Description() string     { return "API documentation (Swagger/OpenAPI) is exposed" }
func (Swagger) OWASP() []string         { return []string{"A05:2021"} }
func (Swagger) ASVS() []string          { return []string{"V14.3.2"} }

func (Swagger) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	// Try a few conventional locations; stop at the first confirmed hit.
	for _, path := range []string{"/swagger/index.html", "/swagger.json", "/openapi.json", "/api-docs"} {
		p, ok, err := fetch(ctx, t, path)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, nil
		}
		if !reachable(p) {
			continue
		}
		body := bodyText(p)
		isSwaggerUI := strings.Contains(strings.ToLower(body), "swagger-ui")
		isSpec := strings.Contains(body, `"swagger"`) || strings.Contains(body, `"openapi"`)
		if !isSwaggerUI && !isSpec {
			continue
		}
		return []core.Finding{{
			Title:      "API documentation is publicly exposed",
			Category:   core.CategoryExposure,
			Severity:   core.SeverityLow,
			Confidence: core.ConfidenceConfirmed,
			Asset:      httpx.Asset(t, p.URL),
			Evidence:   core.Evidence{Request: p.Request, Response: p.Response},
			CWE:        []string{"CWE-200"},
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What: "Interactive API documentation is reachable without authentication at " + p.URL.EscapedPath() + ".",
				Why:  "A full map of every endpoint, parameter and model lets an attacker skip reconnaissance and target the API directly. Docs belong behind auth or off in production.",
				How: []core.Fix{
					{Stack: "gin", Language: "go", Code: `// serve docs only outside production
if gin.Mode() != gin.ReleaseMode {
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
}`},
					{Stack: "generic", Language: "text", Code: "Disable the docs route in production, or require authentication to reach it."},
				},
				Effort:     core.EffortS,
				References: []string{"https://owasp.org/API-Security/"},
			},
		}}, nil
	}
	return nil, nil
}

// Metrics flags an exposed Prometheus-style metrics endpoint.
type Metrics struct{}

func (Metrics) ID() string              { return "exposure.metrics" }
func (Metrics) Category() core.Category { return core.CategoryExposure }
func (Metrics) Mode() core.Mode         { return core.ModeSafe }
func (Metrics) Description() string     { return "A metrics endpoint is publicly reachable" }
func (Metrics) OWASP() []string         { return []string{"A05:2021"} }
func (Metrics) ASVS() []string          { return []string{"V14.3.2"} }

func (Metrics) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := fetch(ctx, t, "/metrics")
	if err != nil || !ok {
		return nil, err
	}
	// Prometheus exposition format: comment lines (# HELP / # TYPE) then samples.
	if !reachable(p) || looksHTML(p) || !strings.Contains(bodyText(p), "# TYPE ") {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "Metrics endpoint is publicly accessible",
		Category:   core.CategoryExposure,
		Severity:   core.SeverityMedium,
		Confidence: core.ConfidenceConfirmed,
		Asset:      httpx.Asset(t, p.URL),
		Evidence:   core.Evidence{Request: p.Request, Response: p.Response},
		CWE:        []string{"CWE-200"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What: "The /metrics endpoint is reachable without authentication.",
			Why:  "Metrics leak internal structure — route names, build versions, queue depths, memory — useful for reconnaissance, and sometimes embed user identifiers. It should be bound to an internal interface.",
			How: []core.Fix{
				{Stack: "generic", Language: "text", Code: "Bind the metrics listener to a private interface, or require auth and restrict it to your monitoring system's source IPs."},
			},
			Effort:     core.EffortS,
			References: []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}}, nil
}

// BackupFiles flags common backup/source-dump filenames left in the web root.
type BackupFiles struct{}

func (BackupFiles) ID() string              { return "exposure.backup-files" }
func (BackupFiles) Category() core.Category { return core.CategoryExposure }
func (BackupFiles) Mode() core.Mode         { return core.ModeSafe }
func (BackupFiles) Description() string     { return "A backup or archive file is reachable" }
func (BackupFiles) OWASP() []string         { return []string{"A05:2021"} }
func (BackupFiles) ASVS() []string          { return []string{"V14.3.2"} }

func (BackupFiles) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	var out []core.Finding
	// Fixed, sorted list for determinism. One finding per reachable archive.
	for _, path := range []string{"/.env.bak", "/backup.sql", "/backup.zip", "/database.sql", "/db.sqlite", "/dump.sql"} {
		p, ok, err := fetch(ctx, t, path)
		if err != nil {
			return out, err
		}
		if !ok {
			return out, nil
		}
		if !reachable(p) || looksHTML(p) || len(p.Body) == 0 {
			continue
		}
		out = append(out, core.Finding{
			Title:      "Backup file is publicly accessible: " + path,
			Category:   core.CategoryExposure,
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceLikely,
			Asset:      httpx.Asset(t, p.URL),
			Location:   path,
			Evidence:   core.Evidence{Request: p.Request, Response: redactedResponse(p), Redacted: true},
			CWE:        []string{"CWE-530"},
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What: "A backup or database dump (" + path + ") is downloadable from the web root.",
				Why:  "Backups contain full data and often credentials. Leaving one in the web root hands over the database in a single request.",
				How: []core.Fix{
					{Stack: "generic", Language: "text", Code: "Store backups outside the web root, and block archive/SQL extensions at the reverse proxy."},
				},
				Effort:     core.EffortS,
				References: []string{"https://owasp.org/www-project-web-security-testing-guide/"},
			},
		})
	}
	return out, nil
}

// DirListing flags an auto-indexed directory.
type DirListing struct{}

func (DirListing) ID() string              { return "exposure.dir-listing" }
func (DirListing) Category() core.Category { return core.CategoryExposure }
func (DirListing) Mode() core.Mode         { return core.ModeSafe }
func (DirListing) Description() string     { return "Directory listing is enabled" }
func (DirListing) OWASP() []string         { return []string{"A05:2021"} }
func (DirListing) ASVS() []string          { return []string{"V14.3.2"} }

func (DirListing) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	for _, path := range []string{"/uploads/", "/files/", "/static/", "/assets/"} {
		p, ok, err := fetch(ctx, t, path)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, nil
		}
		if !reachable(p) {
			continue
		}
		body := bodyText(p)
		if !strings.Contains(body, "Index of ") && !strings.Contains(strings.ToLower(body), "<title>directory listing") {
			continue
		}
		return []core.Finding{{
			Title:      "Directory listing is enabled at " + path,
			Category:   core.CategoryExposure,
			Severity:   core.SeverityLow,
			Confidence: core.ConfidenceConfirmed,
			Asset:      httpx.Asset(t, p.URL),
			Location:   path,
			Evidence:   core.Evidence{Request: p.Request, Response: p.Response},
			CWE:        []string{"CWE-548"},
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What: "The server renders an automatic file index for " + path + ".",
				Why:  "Listings reveal filenames the app never links to — old versions, backups, uploads from other users — turning a directory into a browsable archive.",
				How: []core.Fix{
					{Stack: "nginx", Language: "nginx", Code: `autoindex off;`},
					{Stack: "generic", Language: "text", Code: "Disable automatic directory indexing on the web server."},
				},
				Effort:     core.EffortS,
				References: []string{"https://owasp.org/www-project-web-security-testing-guide/"},
			},
		}}, nil
	}
	return nil, nil
}

// Dashboards flags an unauthenticated admin/ops dashboard, including Scout's
// sibling tools' own UIs (Sentinel, Pulse) left open.
type Dashboards struct{}

func (Dashboards) ID() string              { return "exposure.dashboards" }
func (Dashboards) Category() core.Category { return core.CategoryExposure }
func (Dashboards) Mode() core.Mode         { return core.ModeSafe }
func (Dashboards) Description() string {
	return "An admin or ops dashboard is reachable without authentication"
}
func (Dashboards) OWASP() []string { return []string{"A05:2021"} }
func (Dashboards) ASVS() []string  { return []string{"V14.3.2"} }

func (Dashboards) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.URL == "" {
		return nil, nil
	}
	// The UI probe decides whether the dashboard is mounted here; the API probe
	// decides whether it is actually exposed. These dashboards all serve an
	// unauthenticated HTML shell (that is how the login screen loads), so a 200 on
	// the UI is not evidence — reachable *data* is. See GitHub issue #3.
	probes := []struct{ ui, api, marker string }{
		{"/pulse/ui/", "/pulse/api/overview", "pulse"},
		{"/scout/ui/", "/scout/api/overview", "scout"},
		{"/sentinel/ui", "/sentinel/api/health", "sentinel"},
	}
	var out []core.Finding
	for _, pr := range probes {
		ui, ok, err := fetch(ctx, t, pr.ui)
		// A fetch error or non-2xx (or a different product) just means this
		// dashboard is not mounted here — move on, do not abandon the rest.
		if err != nil || !ok || !reachable(ui) {
			continue
		}
		if !strings.Contains(strings.ToLower(bodyText(ui)), pr.marker) {
			continue
		}
		// The dashboard is mounted. Is its data exposed? Probe the API with no
		// credentials: a 2xx is a real gap; a 401/403/redirect means it is
		// protected and the open HTML shell is just the login page.
		api, ok, err := fetch(ctx, t, pr.api)
		if err != nil || !ok || !reachable(api) {
			continue
		}
		out = append(out, core.Finding{
			Title:      "Dashboard data reachable without authentication: " + pr.ui,
			Category:   core.CategoryExposure,
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceConfirmed,
			Asset:      httpx.Asset(t, ui.URL),
			Location:   pr.ui,
			Evidence:   core.Evidence{Request: api.Request, Response: api.Response, Notes: "unauthenticated GET of " + pr.api + " returned 2xx"},
			CWE:        []string{"CWE-306"},
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What: "The dashboard at " + pr.ui + " is mounted, and its API (" + pr.api + ") returned data without requiring a login.",
				Why:  "An open admin or observability dashboard exposes internal data and controls to anyone who finds the URL.",
				How: []core.Fix{
					{Stack: "generic", Language: "text", Code: "Require authentication for the dashboard API, and refuse the shipped default credentials outside development."},
				},
				Effort:     core.EffortM,
				References: []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"},
			},
		})
	}
	return out, nil
}

// redactedResponse returns the dumped response with its body replaced by a
// note, so evidence from a secret-bearing file never carries the secret.
func redactedResponse(p *httpx.Page) string {
	head := p.Response
	if i := strings.Index(head, "\r\n\r\n"); i >= 0 {
		return head[:i] + "\r\n\r\n[body redacted: potential secrets]"
	}
	return "[response redacted: potential secrets]"
}
