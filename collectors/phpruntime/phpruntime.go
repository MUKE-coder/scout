// Package phpruntime flags a target running an outdated PHP runtime that is
// vulnerable to the "php2shell" flaws — CVE-2026-109618 and CVE-2026-109619,
// two critical (CVSS 9.2) unauthenticated remote-code-execution bugs in PHP
// core, fixed on 2026-10-21 in PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.
//
// It reads the PHP version from the live app's Server / X-Powered-By headers and
// from a repo's Dockerfile base image (FROM php:<version>), then compares it
// against the fixed releases. Safe mode: a single GET plus reading repo files.
//
// Refs:
//   - https://github.com/NCSC-NL/php2shell
//   - https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
package phpruntime

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/collectors/internal/repo"
	"github.com/MUKE-coder/scout/core"
)

func init() { core.Register(PHP2Shell{}) }

// PHP2Shell checks the detected PHP runtime version against the php2shell fixes.
type PHP2Shell struct{}

func (PHP2Shell) ID() string              { return "app.php-runtime-rce" }
func (PHP2Shell) Category() core.Category { return core.CategoryApp }
func (PHP2Shell) Mode() core.Mode         { return core.ModeSafe }
func (PHP2Shell) Description() string {
	return "The PHP runtime version is vulnerable to a known critical RCE (php2shell)"
}
func (PHP2Shell) OWASP() []string { return []string{"A06:2021"} }
func (PHP2Shell) ASVS() []string  { return []string{"V14.2.1"} }

// phpFixed is the first fixed patch per supported branch (php2shell).
var phpFixed = map[[2]int]int{
	{8, 2}: 35,
	{8, 3}: 36,
	{8, 4}: 27,
	{8, 5}: 12,
}

// phpVer matches a PHP version in a header (PHP/8.2.10) or a Docker tag
// (php:8.2.10-fpm-alpine). The patch component is optional.
var phpVer = regexp.MustCompile(`(?i)php[:/]\s*(\d+)\.(\d+)(?:\.(\d+))?`)

// dockerFrom matches a PHP base image in a Dockerfile.
var dockerFrom = regexp.MustCompile(`(?im)^\s*FROM\s+(?:[\w.-]+/)?php:(\d+)\.(\d+)(?:\.(\d+))?`)

type phpHit struct {
	version string // as detected, e.g. "8.2.10" or "8.1"
	major   int
	minor   int
	patch   int // -1 when the patch level is unknown (branch-only)
	source  string
}

func (c PHP2Shell) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	hits := map[string]phpHit{} // keyed by version+source to dedupe

	// Live: Server / X-Powered-By headers.
	if t.URL != "" {
		if page, err := httpx.Get(ctx, t.URL); err == nil && page != nil {
			for _, h := range []string{"X-Powered-By", "Server"} {
				if v := page.Header.Get(h); v != "" {
					if hit, ok := parsePHP(v, h+" header"); ok {
						hits[hit.version+hit.source] = hit
					}
				}
			}
		}
	}
	// Repo: Dockerfile base images.
	if root := repo.Base(t.Repo); root != "" {
		_ = repo.Walk(root, func(f repo.File) error {
			name := strings.ToLower(f.Rel)
			if !strings.Contains(name, "dockerfile") {
				return nil
			}
			for _, m := range dockerFrom.FindAllStringSubmatch(string(f.Data), -1) {
				if hit, ok := hitFrom(m, f.Rel); ok {
					hits[hit.version+hit.source] = hit
				}
			}
			return nil
		})
	}

	var out []core.Finding
	keys := make([]string, 0, len(hits))
	for k := range hits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h := hits[k]
		if vulnerable, why := php2shellVulnerable(h); vulnerable {
			out = append(out, finding(t, h, why))
		}
	}
	return out, nil
}

// parsePHP pulls a PHP version out of a header value.
func parsePHP(value, source string) (phpHit, bool) {
	m := phpVer.FindStringSubmatch(value)
	if m == nil {
		return phpHit{}, false
	}
	return hitFrom(m, source)
}

// hitFrom builds a phpHit from a regex match of [full, major, minor, patch?].
func hitFrom(m []string, source string) (phpHit, bool) {
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return phpHit{}, false
	}
	patch := -1
	ver := fmt.Sprintf("%d.%d", major, minor)
	if m[3] != "" {
		if p, err := strconv.Atoi(m[3]); err == nil {
			patch = p
			ver = fmt.Sprintf("%d.%d.%d", major, minor, patch)
		}
	}
	return phpHit{version: ver, major: major, minor: minor, patch: patch, source: source}, true
}

// php2shellVulnerable reports whether a detected PHP version is exposed to
// php2shell, with a short reason.
func php2shellVulnerable(h phpHit) (bool, string) {
	// End-of-life branches (anything before 8.2) get no official fix.
	if h.major < 8 || (h.major == 8 && h.minor < 2) {
		return true, "PHP " + h.version + " is end-of-life and unpatched against php2shell"
	}
	fixed, ok := phpFixed[[2]int{h.major, h.minor}]
	if !ok {
		return false, "" // 8.6+ or newer: assume patched
	}
	if h.patch < 0 {
		return false, "" // branch only (e.g. php:8.2) — patch unknown, don't guess
	}
	if h.patch < fixed {
		return true, fmt.Sprintf("PHP %s is below the fixed %d.%d.%d", h.version, h.major, h.minor, fixed)
	}
	return false, ""
}

func finding(t core.Target, h phpHit, why string) core.Finding {
	loc := "CVE-2026-109618 / CVE-2026-109619"
	fix := "Update PHP to a fixed release: 8.2.35, 8.3.36, 8.4.27 or 8.5.12 (or your distro's backport). " +
		"If you cannot patch immediately, set session.upload_progress.enabled = Off in php.ini and restart PHP workers " +
		"(a partial mitigation), and keep end-of-life PHP off the public internet."
	return core.Finding{
		Title:      "Outdated PHP runtime " + h.version + ": critical unauthenticated RCE (php2shell)",
		Category:   core.CategoryApp,
		Severity:   core.SeverityCritical,
		Confidence: core.ConfidenceConfirmed,
		Asset:      core.Asset{Kind: core.AssetURL, Value: "PHP " + h.version, Host: t.Host(), Criticality: t.Criticality},
		Location:   loc,
		Evidence:   core.Evidence{Matched: "PHP " + h.version + " (from " + h.source + ")", Notes: why},
		CWE:        []string{"CWE-416", "CWE-787"},
		OWASP:      []string{"A06:2021"},
		Remediation: core.Remediation{
			What: "The server runs PHP " + h.version + ", which is vulnerable to php2shell " +
				"(CVE-2026-109618 and CVE-2026-109619): two critical, unauthenticated remote-code-execution flaws in PHP core.",
			Why:    "These are CVSS 9.2 unauthenticated RCEs in the PHP runtime itself — exploitable before your application code runs (mod_php is highest risk) and demonstrated against WordPress, Drupal and Joomla. " + why + ".",
			How:    []core.Fix{{Stack: "php", Language: "text", Code: fix}},
			Effort: core.EffortM,
			References: []string{
				"https://github.com/NCSC-NL/php2shell",
				"https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities",
				"https://nvd.nist.gov/vuln/detail/CVE-2026-109618",
				"https://nvd.nist.gov/vuln/detail/CVE-2026-109619",
			},
		},
	}
}
