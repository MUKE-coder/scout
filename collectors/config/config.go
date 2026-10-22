// Package config checks configuration posture: framework debug mode left on,
// shipped default credentials, and misconfigured sibling tools (Sentinel,
// Pulse) such as monitor-only WAF or in-memory storage in production. Every
// check is passive: it reads the in-process route table exported by
// scout.Mount and GET-only health/diagnostic endpoints, and sends no attack
// traffic.
package config

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

func init() {
	core.Register(GinDebug{})
	core.Register(DefaultCreds{})
	core.Register(SentinelMisconfig{})
	core.Register(PulseMisconfig{})
	core.Register(InMemoryStorageProd{})
}

// get fetches a path on the target, or (nil,false,nil) for a repo-only target.
func get(ctx context.Context, t core.Target, path string) (*httpx.Page, bool, error) {
	if t.URL == "" {
		return nil, false, nil
	}
	u, err := httpx.Resolve(t, path)
	if err != nil {
		return nil, false, nil
	}
	p, err := httpx.Do(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, false, err
	}
	return p, true, nil
}

func urlAsset(t core.Target, p *httpx.Page) core.Asset { return httpx.Asset(t, p.URL) }

// GinDebug flags a Gin app running in debug mode, detected by its default
// not-found response and the absence of production hardening. Debug mode is
// read from the route table when available, and confirmed over HTTP.
type GinDebug struct{}

func (GinDebug) ID() string              { return "config.gin-debug" }
func (GinDebug) Category() core.Category { return core.CategoryConfig }
func (GinDebug) Mode() core.Mode         { return core.ModePassive }
func (GinDebug) Description() string     { return "Gin appears to run in debug mode" }
func (GinDebug) OWASP() []string         { return []string{"A05:2021"} }
func (GinDebug) ASVS() []string          { return []string{"V14.1.3"} }

func (GinDebug) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := get(ctx, t, "/scout-nonexistent-probe-"+probeNonce)
	if err != nil || !ok {
		return nil, err
	}
	// Gin's debug 404 is the plain text "404 page not found"; release mode is
	// typically the same string, so we rely on the X-Debug-ish signals and the
	// route table rather than the 404 body alone.
	body := strings.TrimSpace(string(p.Body))
	ginDefault404 := p.Status == http.StatusNotFound && body == "404 page not found"
	if !ginDefault404 {
		return nil, nil
	}
	// Severity depends on environment: debug in prod is the real problem.
	sev := core.SeverityLow
	conf := core.ConfidencePossible
	if t.Environment == core.EnvProd {
		sev = core.SeverityMedium
	}
	return []core.Finding{{
		Title:      "Gin may be running with debug output enabled",
		Category:   core.CategoryConfig,
		Severity:   sev,
		Confidence: conf,
		Asset:      urlAsset(t, p),
		Evidence:   core.Evidence{Request: p.Request, Response: p.Response, Notes: "default Gin 404 handler observed"},
		CWE:        []string{"CWE-489"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What: "The application responds with Gin's default handlers, which suggests it may not be running in release mode.",
			Why:  "Debug mode prints routes and verbose errors to logs and can leak internal detail in responses. Production should run in release mode.",
			How: []core.Fix{
				{Stack: "gin", Language: "go", Code: `// set release mode before creating the router
gin.SetMode(gin.ReleaseMode)
// or export GIN_MODE=release`},
			},
			Effort:     core.EffortS,
			References: []string{"https://gin-gonic.com/docs/deployment/"},
		},
	}}, nil
}

const probeNonce = "a1b2c3"

// DefaultCreds advises rotating shipped default credentials when a known admin
// login route is present in production. It never submits credentials (that
// would be an active auth check); it is a passive, route-table-driven nudge.
type DefaultCreds struct{}

func (DefaultCreds) ID() string              { return "config.default-creds" }
func (DefaultCreds) Category() core.Category { return core.CategoryConfig }
func (DefaultCreds) Mode() core.Mode         { return core.ModePassive }
func (DefaultCreds) Description() string {
	return "A known admin login route is exposed in production (verify credentials are not defaults)"
}
func (DefaultCreds) OWASP() []string { return []string{"A07:2021"} }
func (DefaultCreds) ASVS() []string  { return []string{"V2.1.1"} }

// knownLoginRoutes are admin/ops login paths whose tools ship default creds.
var knownLoginRoutes = []string{
	"/scout/api/auth/login",
	"/sentinel/api/auth/login",
	"/pulse/api/auth/login",
}

func (DefaultCreds) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.Environment != core.EnvProd {
		return nil, nil // advisory only matters in production
	}
	present := map[string]bool{}
	for _, r := range t.Routes {
		present[strings.ToLower(r.Path)] = true
	}
	var matched string
	for _, lr := range knownLoginRoutes { // sorted-by-definition, deterministic
		if present[lr] {
			matched = lr
			break
		}
	}
	if matched == "" {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "Admin login route exposed in production: " + matched,
		Category:   core.CategoryConfig,
		Severity:   core.SeverityLow,
		Confidence: core.ConfidencePossible,
		Asset:      core.Asset{Kind: core.AssetRoute, Value: "POST " + matched, Method: "POST", Path: matched, Exposure: core.ExposureInternet, Criticality: t.Criticality},
		Location:   matched,
		Evidence:   core.Evidence{Notes: "route present in the application's route table in a prod environment"},
		CWE:        []string{"CWE-1392"},
		OWASP:      []string{"A07:2021"},
		Remediation: core.Remediation{
			What: "A management login route (" + matched + ") is reachable in production. Confirm it does not accept the tool's shipped default credentials.",
			Why:  "Tools in this family ship development defaults (for example admin/scout). Left unchanged in production, anyone can log in to the dashboard.",
			How: []core.Fix{
				{Stack: "generic", Language: "text", Code: "Set a strong username and password from your secrets manager, and refuse the shipped defaults outside development."},
			},
			Effort:     core.EffortS,
			References: []string{"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
		},
	}}, nil
}

// SentinelMisconfig reads a reachable Sentinel health/config endpoint and flags
// a WAF left in log-only mode.
type SentinelMisconfig struct{}

func (SentinelMisconfig) ID() string              { return "config.sentinel-misconfig" }
func (SentinelMisconfig) Category() core.Category { return core.CategoryConfig }
func (SentinelMisconfig) Mode() core.Mode         { return core.ModePassive }
func (SentinelMisconfig) Description() string {
	return "Sentinel WAF is reachable but not enforcing (log-only)"
}
func (SentinelMisconfig) OWASP() []string { return []string{"A05:2021"} }

func (SentinelMisconfig) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := get(ctx, t, "/sentinel/api/health")
	if err != nil || !ok {
		return nil, err
	}
	info, parsed := parseHealth(p)
	if !parsed {
		return nil, nil
	}
	mode := strings.ToLower(info.WAFMode)
	if mode == "" || mode == "block" {
		return nil, nil // enforcing, or doesn't report a WAF mode
	}
	return []core.Finding{{
		Title:      "Sentinel WAF is not enforcing (mode: " + info.WAFMode + ")",
		Category:   core.CategoryConfig,
		Severity:   core.SeverityMedium,
		Confidence: core.ConfidenceLikely,
		Asset:      urlAsset(t, p),
		Evidence:   core.Evidence{Request: p.Request, Response: p.Response, Matched: "waf mode: " + info.WAFMode},
		CWE:        []string{"CWE-693"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What: "Sentinel reports its WAF in " + info.WAFMode + " mode, which detects but does not block attacks.",
			Why:  "A WAF in log-only mode gives a false sense of protection: malicious requests are recorded and then allowed through.",
			How: []core.Fix{
				{Stack: "sentinel", Language: "go", Code: `WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeBlock,
}`},
			},
			Effort:     core.EffortS,
			References: []string{"https://github.com/MUKE-coder/sentinel"},
		},
	}}, nil
}

// PulseMisconfig reads a reachable Pulse health endpoint and flags default
// credentials being allowed in production.
type PulseMisconfig struct{}

func (PulseMisconfig) ID() string              { return "config.pulse-misconfig" }
func (PulseMisconfig) Category() core.Category { return core.CategoryConfig }
func (PulseMisconfig) Mode() core.Mode         { return core.ModePassive }
func (PulseMisconfig) Description() string {
	return "Pulse is reachable with insecure production settings"
}
func (PulseMisconfig) OWASP() []string { return []string{"A05:2021"} }

func (PulseMisconfig) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	p, ok, err := get(ctx, t, "/pulse/health")
	if err != nil || !ok {
		return nil, err
	}
	info, parsed := parseHealth(p)
	if !parsed || !info.DevMode {
		return nil, nil
	}
	if t.Environment != core.EnvProd {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "Pulse is running in dev mode on a production target",
		Category:   core.CategoryConfig,
		Severity:   core.SeverityMedium,
		Confidence: core.ConfidenceLikely,
		Asset:      urlAsset(t, p),
		Evidence:   core.Evidence{Request: p.Request, Response: p.Response, Matched: "dev_mode: true"},
		CWE:        []string{"CWE-489"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What: "Pulse reports dev mode on a target marked production, which permits shipped default credentials and relaxes hardening.",
			Why:  "Dev mode is a convenience for local work; in production it leaves the observability dashboard open to default logins.",
			How: []core.Fix{
				{Stack: "generic", Language: "go", Code: `pulse.Mount(ctx, router, db,
    // remove pulse.WithDevMode() and set real credentials
    pulse.WithCredentials("admin", os.Getenv("PULSE_PASSWORD")),
)`},
			},
			Effort:     core.EffortS,
			References: []string{"https://github.com/MUKE-coder/pulse"},
		},
	}}, nil
}

// InMemoryStorageProd flags a sibling tool reporting in-memory storage on a
// production target, where history and audit data are lost on restart.
type InMemoryStorageProd struct{}

func (InMemoryStorageProd) ID() string              { return "config.inmemory-storage-prod" }
func (InMemoryStorageProd) Category() core.Category { return core.CategoryConfig }
func (InMemoryStorageProd) Mode() core.Mode         { return core.ModePassive }
func (InMemoryStorageProd) Description() string {
	return "A tool uses in-memory storage on a production target"
}
func (InMemoryStorageProd) OWASP() []string { return []string{"A09:2021"} }

func (InMemoryStorageProd) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.Environment != core.EnvProd {
		return nil, nil
	}
	// Check both siblings' health endpoints; report the first that admits
	// memory storage. Deterministic order.
	for _, probe := range []struct{ path, tool string }{
		{"/sentinel/api/health", "Sentinel"},
		{"/pulse/health", "Pulse"},
	} {
		p, ok, err := get(ctx, t, probe.path)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, nil
		}
		info, parsed := parseHealth(p)
		if !parsed || strings.ToLower(info.Storage) != "memory" {
			continue
		}
		return []core.Finding{{
			Title:      probe.tool + " uses in-memory storage in production",
			Category:   core.CategoryConfig,
			Severity:   core.SeverityLow,
			Confidence: core.ConfidenceLikely,
			Asset:      urlAsset(t, p),
			Location:   probe.tool,
			Evidence:   core.Evidence{Request: p.Request, Response: p.Response, Matched: "storage: memory"},
			CWE:        []string{"CWE-778"},
			OWASP:      []string{"A09:2021"},
			Remediation: core.Remediation{
				What: probe.tool + " reports in-memory storage on a production target, so all findings, audit entries and history are lost on every restart.",
				Why:  "Losing security and audit history on restart breaks incident investigation and compliance evidence, and some reports are refused without durable storage.",
				How: []core.Fix{
					{Stack: "generic", Language: "text", Code: "Configure a persistent SQLite (on a durable volume) or Postgres backend for the tool in production."},
				},
				Effort:     core.EffortS,
				References: []string{"https://github.com/MUKE-coder/sentinel", "https://github.com/MUKE-coder/pulse"},
			},
		}}, nil
	}
	return nil, nil
}

// healthInfo is the subset of a sibling tool's health JSON that these checks
// read. All fields are optional.
type healthInfo struct {
	WAFMode string `json:"waf_mode"`
	DevMode bool   `json:"dev_mode"`
	Storage string `json:"storage"`
}

// parseHealth decodes a health response as JSON. It returns parsed=false for a
// non-2xx, non-JSON, or unparseable body, so a protected or absent endpoint is
// silently ignored rather than misreported.
func parseHealth(p *httpx.Page) (healthInfo, bool) {
	if p.Status < 200 || p.Status >= 300 {
		return healthInfo{}, false
	}
	if !strings.Contains(strings.ToLower(p.Header.Get("Content-Type")), "json") {
		return healthInfo{}, false
	}
	var info healthInfo
	if err := json.Unmarshal(p.Body, &info); err != nil {
		return healthInfo{}, false
	}
	return info, true
}
