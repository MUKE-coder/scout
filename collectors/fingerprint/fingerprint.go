// Package fingerprint flags information that helps an attacker fingerprint the
// stack: software/version banners in response headers, and directory listings
// (autoindex) that enumerate files. Both checks are safe-mode: they send
// ordinary GET requests through the guarded client and read the responses;
// they send no attack payloads.
package fingerprint

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

func init() {
	core.Register(VersionDisclosure{})
	core.Register(DirectoryListing{})
}

// --- version / software banners ----------------------------------------

type VersionDisclosure struct{}

func (VersionDisclosure) ID() string              { return "app.version-disclosure" }
func (VersionDisclosure) Category() core.Category { return core.CategoryApp }
func (VersionDisclosure) Mode() core.Mode         { return core.ModeSafe }
func (VersionDisclosure) Description() string {
	return "Response headers reveal the server software or framework version"
}
func (VersionDisclosure) OWASP() []string { return []string{"A05:2021"} }
func (VersionDisclosure) ASVS() []string  { return []string{"V14.3.2"} }

// bannerHeaders are response headers that commonly leak the stack. The bool is
// whether a bare value (no version) is still worth reporting: a technology name
// with no version (e.g. "Next.js") is low-value fingerprinting, while a version
// string maps the host to known CVEs and is the real concern.
var bannerHeaders = []string{
	"Server",
	"X-Powered-By",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
	"X-Generator",
	"X-Runtime",
	"X-Drupal-Cache",
}

// versionRe matches a version-like token (1.2, 1.2.3, 2019) inside a header.
var versionRe = regexp.MustCompile(`\b\d+(?:\.\d+){1,}\b`)

func (c VersionDisclosure) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.URL == "" {
		return nil, nil
	}
	page, err := httpx.Get(ctx, t.URL)
	if err != nil || page == nil {
		return nil, err
	}

	var out []core.Finding
	for _, h := range bannerHeaders {
		val := strings.TrimSpace(page.Header.Get(h))
		if val == "" {
			continue
		}
		hasVersion := versionRe.MatchString(val)
		sev := core.SeverityLow
		if hasVersion {
			sev = core.SeverityMedium // a version maps directly to known CVEs
		}
		out = append(out, core.Finding{
			Title:       "Version/software disclosed in " + h + " header",
			Category:    core.CategoryApp,
			Severity:    sev,
			Confidence:  core.ConfidenceConfirmed, // read straight from the response
			Asset:       assetFor(t, page.URL),
			Location:    h,
			Evidence:    core.Evidence{Matched: h + ": " + val},
			CWE:         []string{"CWE-200"},
			OWASP:       []string{"A05:2021"},
			Remediation: remediationBanner(h),
		})
	}
	return out, nil
}

func remediationBanner(header string) core.Remediation {
	return core.Remediation{
		What: "The server returns a " + header + " header that names the software or its version.",
		Why:  "It hands an attacker a free map from your host to known CVEs for that exact version, and narrows which exploits to try.",
		How: []core.Fix{
			{Stack: "next.js", Language: "js", Code: "// next.config.js\nmodule.exports = { poweredByHeader: false }"},
			{Stack: "nginx", Language: "text", Code: "server_tokens off;"},
			{Stack: "express", Language: "js", Code: "app.disable('x-powered-by')"},
		},
		Effort:     core.EffortS,
		References: []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"},
	}
}

// --- directory listing / autoindex -------------------------------------

type DirectoryListing struct{}

func (DirectoryListing) ID() string              { return "app.directory-listing" }
func (DirectoryListing) Category() core.Category { return core.CategoryApp }
func (DirectoryListing) Mode() core.Mode         { return core.ModeSafe }
func (DirectoryListing) Description() string {
	return "A directory returns an autoindex file listing"
}
func (DirectoryListing) OWASP() []string { return []string{"A05:2021"} }
func (DirectoryListing) ASVS() []string  { return []string{"V14.3.3"} }

// commonDirs are paths that frequently have autoindex left on. The trailing
// slash asks the server for a listing rather than a file.
var commonDirs = []string{
	"/uploads/", "/files/", "/images/", "/img/", "/assets/", "/static/",
	"/public/", "/media/", "/backup/", "/backups/", "/data/", "/tmp/",
	"/downloads/", "/docs/", "/.well-known/",
}

// listingSignatures identify an autoindex page across common servers.
var listingSignatures = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`(?i)<title>\s*Index of /`), "Apache/nginx autoindex"},
	{regexp.MustCompile(`(?i)<h1>\s*Index of /`), "Apache/nginx autoindex"},
	{regexp.MustCompile(`(?i)Directory listing for /`), "Python http.server listing"},
	{regexp.MustCompile(`(?i)\[To Parent Directory\]`), "IIS directory listing"},
}

func (c DirectoryListing) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.URL == "" {
		return nil, nil
	}
	var out []core.Finding
	seen := map[string]bool{}
	for _, dir := range commonDirs {
		u, err := httpx.Resolve(t, dir)
		if err != nil {
			continue
		}
		page, err := httpx.Get(ctx, u.String())
		if err != nil || page.Status < 200 || page.Status > 299 {
			continue
		}
		body := string(page.Body)
		for _, sig := range listingSignatures {
			if !sig.re.MatchString(body) {
				continue
			}
			if seen[dir] {
				break
			}
			seen[dir] = true
			out = append(out, core.Finding{
				Title:      "Directory listing enabled: " + dir,
				Category:   core.CategoryApp,
				Severity:   core.SeverityMedium,
				Confidence: core.ConfidenceConfirmed,
				Asset:      assetFor(t, page.URL),
				Location:   dir,
				Evidence:   core.Evidence{Request: page.Request, Matched: sig.what + " at " + dir},
				CWE:        []string{"CWE-548"},
				OWASP:      []string{"A05:2021"},
				Remediation: core.Remediation{
					What: "The web server returns a browsable listing of a directory's contents.",
					Why:  "It exposes file names, backups and source left in the directory, which an attacker enumerates and downloads directly.",
					How: []core.Fix{
						{Stack: "nginx", Language: "text", Code: "autoindex off;  # (it is off by default; remove any 'autoindex on')"},
						{Stack: "apache", Language: "text", Code: "Options -Indexes"},
					},
					Effort:     core.EffortS,
					References: []string{"https://owasp.org/www-community/attacks/Forced_browsing"},
				},
			})
			break
		}
	}
	return out, nil
}

// assetFor builds a URL asset for a finding, falling back to the target URL.
func assetFor(t core.Target, u *url.URL) core.Asset {
	if u != nil {
		return httpx.Asset(t, u)
	}
	return core.Asset{Kind: core.AssetURL, Value: t.URL, Criticality: t.Criticality}
}
