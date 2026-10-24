// Package clientlib finds known-vulnerable client-side libraries loaded by a
// live page. It reads the <script src> / <link href> URLs, extracts each
// library's name and version (from CDN paths and versioned filenames), and
// matches them against known vulnerabilities via the intel layer (OSV), enriched
// with exploitation intelligence (CISA KEV + FIRST EPSS).
//
// This is the black-box complement to software composition analysis: it needs no
// repository or lockfile, only the running app — the version is right there in
// the asset URL (jquery-3.4.1.min.js, cdn.jsdelivr.net/npm/vue@2.6.10, …).
//
// Safe mode: one GET of the page through the guarded client; no attack payloads.
package clientlib

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/intel"
)

func init() { core.Register(Scan{}) }

// Injectable for tests.
var (
	db     intel.DB     = intel.NewOSV()
	enrich enricherFunc = intel.NewEnricher().Enrich
)

type enricherFunc func(ctx context.Context, vulns []*intel.Vuln)

// Scan reports client-side libraries with known vulnerabilities.
type Scan struct{}

func (Scan) ID() string              { return "app.vulnerable-js-lib" }
func (Scan) Category() core.Category { return core.CategoryApp }
func (Scan) Mode() core.Mode         { return core.ModeSafe }
func (Scan) Description() string {
	return "A client-side JS/CSS library with a known vulnerability is loaded by the page"
}
func (Scan) OWASP() []string { return []string{"A06:2021"} }
func (Scan) ASVS() []string  { return []string{"V14.2.1"} }

func (Scan) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.URL == "" {
		return nil, nil
	}
	page, err := httpx.Get(ctx, t.URL)
	if err != nil || page == nil {
		return nil, nil
	}
	libs := detect(page.Body) // map "pkg@ver" -> source URL
	if len(libs) == 0 {
		return nil, nil
	}

	pkgs := make([]intel.Package, 0, len(libs))
	srcOf := make([]string, 0, len(libs))
	keys := make([]string, 0, len(libs))
	for k := range libs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name, ver, _ := strings.Cut(k, "@")
		pkgs = append(pkgs, intel.Package{
			Ecosystem: "npm", Name: name, Version: ver,
			PURL: "pkg:npm/" + name + "@" + ver, File: libs[k],
		})
		srcOf = append(srcOf, libs[k])
	}

	results, err := db.Query(ctx, pkgs)
	if err != nil {
		return nil, nil // database unreachable — skip, don't fail the scan
	}
	if enrich != nil {
		var flat []*intel.Vuln
		for i := range results {
			for j := range results[i] {
				flat = append(flat, &results[i][j])
			}
		}
		enrich(ctx, flat)
	}

	var out []core.Finding
	seen := map[string]bool{}
	for i, vulns := range results {
		if i >= len(pkgs) {
			break
		}
		for _, v := range vulns {
			key := pkgs[i].Name + pkgs[i].Version + v.ID
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, finding(t, pkgs[i], srcOf[i], v, page.URL))
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Severity != out[b].Severity {
			return out[a].Severity > out[b].Severity
		}
		return out[a].Asset.Value < out[b].Asset.Value
	})
	return out, nil
}

// --- detection -------------------------------------------------------------

var srcAttr = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+)["']`)

// detect returns a map of "npmName@version" -> the asset URL it was found in.
func detect(body []byte) map[string]string {
	found := map[string]string{}
	for _, m := range srcAttr.FindAllSubmatch(body, -1) {
		raw := string(m[1])
		if name, ver, ok := parseLib(raw); ok {
			found[name+"@"+ver] = raw
		}
	}
	return found
}

// knownLibs maps a detected (normalized) library identifier to its npm package
// name. Restricting to a curated set of well-known, frequently-vulnerable
// front-end libraries keeps false positives down (a site's own app-1.2.3.js is
// ignored).
var knownLibs = map[string]string{
	"jquery": "jquery", "jquery-ui": "jquery-ui", "jquery.ui": "jquery-ui",
	"bootstrap": "bootstrap", "angular": "angular", "angular-route": "angular-route",
	"angularjs": "angular", "vue": "vue", "react": "react", "react-dom": "react-dom", "lodash": "lodash",
	"underscore": "underscore", "moment": "moment", "axios": "axios", "d3": "d3",
	"handlebars": "handlebars", "backbone": "backbone", "knockout": "knockout",
	"dompurify": "dompurify", "select2": "select2", "tinymce": "tinymce",
	"ckeditor": "ckeditor", "mustache": "mustache", "ember": "ember-source",
	"swagger-ui": "swagger-ui", "chart": "chart.js", "chartjs": "chart.js",
	"popper": "@popperjs/core", "bootstrap-select": "bootstrap-select",
	"video": "video.js", "videojs": "video.js", "sanitize-html": "sanitize-html",
	"marked": "marked", "next": "next", "nuxt": "nuxt", "jquery-validate": "jquery-validation",
}

var (
	reAtVer  = regexp.MustCompile(`(?:^|[/@])([a-z0-9_.-]+)@(\d+\.\d+(?:\.\d+)?)`)
	reCdnjs  = regexp.MustCompile(`(?:ajax/)?libs/([a-z0-9_.-]+)/(\d+\.\d+(?:\.\d+)?)`)
	reFile   = regexp.MustCompile(`^([a-z][a-z0-9_.]*?)[-.](\d+\.\d+(?:\.\d+)?)`)
	reVerNum = regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)?)`)
	suffixes = []string{".min", ".slim", ".umd", ".common", ".production", ".development", ".esm", ".core", ".bundle", ".pack", ".prod", ".dev"}
)

// parseLib extracts a known library's npm name and version from an asset URL.
func parseLib(raw string) (name, version string, ok bool) {
	low := strings.ToLower(raw)

	// 1. scoped/CDN "<name>@<ver>" (jsdelivr, unpkg).
	if m := reAtVer.FindStringSubmatch(low); m != nil {
		if n, okn := resolveLib(m[1]); okn {
			return n, m[2], true
		}
	}
	// 2. cdnjs "libs/<name>/<ver>/".
	if m := reCdnjs.FindStringSubmatch(low); m != nil {
		if n, okn := resolveLib(m[1]); okn {
			return n, m[2], true
		}
	}

	// Work on the basename for the remaining patterns.
	base := low
	if u, err := url.Parse(low); err == nil {
		base = path.Base(u.Path)
		// 4. "?ver=" / "?v=" (WordPress-style enqueues): name from basename.
		if q := u.Query(); q.Get("ver") != "" || q.Get("v") != "" {
			ver := q.Get("ver")
			if ver == "" {
				ver = q.Get("v")
			}
			if vm := reVerNum.FindStringSubmatch(ver); vm != nil {
				if n, okn := resolveLib(stripExt(base)); okn {
					return n, vm[1], true
				}
			}
		}
	}
	// 3. versioned filename "<name>-<ver>.min.js".
	if m := reFile.FindStringSubmatch(base); m != nil {
		if n, okn := resolveLib(m[1]); okn {
			return n, m[2], true
		}
	}
	return "", "", false
}

// resolveLib normalizes an identifier (dropping build suffixes) and maps it to a
// known npm package name.
func resolveLib(id string) (string, bool) {
	id = strings.TrimSuffix(id, ".js")
	id = strings.TrimSuffix(id, ".css")
	for _, s := range suffixes {
		id = strings.TrimSuffix(id, s)
	}
	n, ok := knownLibs[id]
	return n, ok
}

// stripExt removes the file extension and any build suffixes from a basename.
func stripExt(base string) string {
	base = strings.TrimSuffix(base, ".js")
	base = strings.TrimSuffix(base, ".css")
	base = strings.TrimSuffix(base, ".min")
	return base
}

// --- finding ---------------------------------------------------------------

func finding(t core.Target, p intel.Package, src string, v intel.Vuln, pageURL *url.URL) core.Finding {
	sev, conf := severity(v.Severity)
	if v.KEV && sev < core.SeverityHigh {
		sev, conf = core.SeverityHigh, core.ConfidenceConfirmed
	}
	id := v.ID
	if len(v.Aliases) > 0 {
		id = strings.Join(append([]string{v.ID}, v.Aliases...), " / ")
	}
	title := "Outdated client-side library " + p.Name + "@" + p.Version
	if v.KEV {
		title = "[Exploited] " + title
	}
	if v.Summary != "" {
		title += ": " + v.Summary
	}
	fix := "Update " + p.Name + " to a fixed version and redeploy the asset."
	if v.Fixed != "" {
		fix = "Update " + p.Name + " to " + v.Fixed + " or later and redeploy the asset."
	}
	refs := []string{v.Ref}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			refs = append(refs, "https://nvd.nist.gov/vuln/detail/"+a)
		}
	}
	why := "This front-end library is served to every visitor; a known client-side flaw (often DOM XSS or prototype pollution) is exploitable directly in your users' browsers."
	if v.KEV {
		why = "This CVE is in CISA's Known Exploited Vulnerabilities catalog — it is being exploited in the wild right now."
		if v.Ransomware {
			why += " It has been used in ransomware campaigns."
		}
		refs = append(refs, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
	}

	notes := "loaded from " + src + " — " + id
	if sig := exploitSignal(v); sig != "" {
		notes += " · " + sig
	}

	host := ""
	if pageURL != nil {
		host = pageURL.Host
	}
	return core.Finding{
		Title:      title,
		Category:   core.CategoryApp,
		Severity:   sev,
		Confidence: conf,
		Asset:      core.Asset{Kind: core.AssetURL, Value: p.Name + "@" + p.Version, Host: host, Criticality: t.Criticality},
		Location:   id,
		Evidence:   core.Evidence{Notes: notes},
		CWE:        []string{"CWE-1395"},
		OWASP:      []string{"A06:2021"},
		Remediation: core.Remediation{
			What:       "The page loads a third-party client-side library (" + p.Name + " " + p.Version + ") with a known, published vulnerability (" + id + ").",
			Why:        why,
			How:        []core.Fix{{Stack: "web", Language: "text", Code: fix + "\nPrefer a maintained version pinned by integrity (Subresource Integrity) from a trusted CDN or your own bundle."}},
			Effort:     core.EffortS,
			References: refs,
		},
	}
}

func exploitSignal(v intel.Vuln) string {
	var parts []string
	if v.KEV {
		s := "CISA KEV: exploited in the wild"
		if v.Ransomware {
			s = "CISA KEV: exploited in the wild (ransomware)"
		}
		parts = append(parts, s)
	}
	if v.EPSS > 0 {
		parts = append(parts, fmt.Sprintf("EPSS %.0f%% (p%.0f)", v.EPSS*100, v.EPSSPctl*100))
	}
	return strings.Join(parts, " · ")
}

func severity(label string) (core.Severity, core.Confidence) {
	switch label {
	case "Critical":
		return core.SeverityCritical, core.ConfidenceConfirmed
	case "High":
		return core.SeverityHigh, core.ConfidenceConfirmed
	case "Medium":
		return core.SeverityMedium, core.ConfidenceConfirmed
	case "Low":
		return core.SeverityLow, core.ConfidenceConfirmed
	default:
		return core.SeverityMedium, core.ConfidenceLikely
	}
}
