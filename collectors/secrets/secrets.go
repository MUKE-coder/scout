// Package secrets scans a target's source tree (Target.Repo) for credentials
// that should never be committed: cloud keys, private keys, tokens and
// obvious password/secret assignments. It reads files only — passive, no
// network — and reports each hit as a file:line finding with the secret
// value masked in the evidence.
package secrets

import (
	"context"
	"regexp"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/repo"
	"github.com/MUKE-coder/scout/core"
)

func init() { core.Register(Scanner{}) }

// rule matches one kind of secret.
type rule struct {
	id   string
	desc string
	re   *regexp.Regexp
	sev  core.Severity
}

// rules are deliberately specific to keep false positives low. The generic
// assignment rule requires a quoted, reasonably long value next to a
// sensitive key name.
var rules = []rule{
	{"aws-access-key", "AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), core.SeverityHigh},
	{"private-key", "Private key block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), core.SeverityCritical},
	{"google-api-key", "Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), core.SeverityHigh},
	{"slack-token", "Slack token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`), core.SeverityHigh},
	{"github-token", "GitHub token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,}\b`), core.SeverityHigh},
	{"stripe-key", "Stripe secret key", regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{16,}\b`), core.SeverityCritical},
	{"anthropic-key", "Anthropic API key", regexp.MustCompile(`\bsk-ant-[0-9A-Za-z_\-]{20,}\b`), core.SeverityHigh},
	{"openai-key", "OpenAI API key", regexp.MustCompile(`\bsk-(?:proj-)?[0-9A-Za-z]{20,}\b`), core.SeverityHigh},
	{"huggingface-token", "Hugging Face token", regexp.MustCompile(`\bhf_[0-9A-Za-z]{30,}\b`), core.SeverityHigh},
	{"replicate-token", "Replicate API token", regexp.MustCompile(`\br8_[0-9A-Za-z]{30,}\b`), core.SeverityHigh},
	{"jwt", "Hard-coded JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), core.SeverityMedium},
	{"generic-secret", "Hard-coded secret assignment", regexp.MustCompile(`(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key|client[_-]?secret)\s*(?::=|[:=])\s*["'][^"'\s]{8,}["']`), core.SeverityMedium},
}

// placeholder values that look like secrets but are not.
var placeholder = regexp.MustCompile(`(?i)(example|changeme|your[_-]?|placeholder|dummy|test|xxxx|\*\*\*\*|<[a-z]|\$\{|redacted|sample)`)

// suppress matches inline "a human reviewed this" annotations (gosec, Biome,
// ESLint, Semgrep). Honouring them is the ecosystem convention.
var suppress = regexp.MustCompile(`(?i)(#nosec|nolint|nosemgrep|biome-ignore|eslint-disable|lgtm\[|noqa)`)

// routeOrPath marks a quoted value that is a URL path or route, not a credential
// — it starts with "/" or contains a scheme. These match generic-secret when the
// key happens to contain a word like PASSWORD (e.g. RESET_PASSWORD: "/auth/...").
var routeOrPath = regexp.MustCompile(`^/|://`)

// envVarName marks a quoted value that is the NAME of an environment variable
// (SecretEnv: "UNUSED_SECRET"), i.e. a reference to where a secret lives, not the
// secret itself.
var envVarName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// strongRules are specific enough that a hit is a real secret even in a test
// file or doc, so they keep their severity and the exposed-secret tag there.
var strongRules = map[string]bool{"aws-access-key": true, "private-key": true, "google-api-key": true, "slack-token": true, "github-token": true, "stripe-key": true, "anthropic-key": true, "openai-key": true, "huggingface-token": true, "replicate-token": true}

// testOrDoc matches paths where a "secret" is probably a fixture or example.
var testOrDoc = regexp.MustCompile(`(?i)(_test\.|\.test\.|\.spec\.|/__tests__/|/tests?/|/testdata/|/learning-guides/|/docs?/|\.md$|\.txt$)`)

// Scanner finds committed secrets in a repository.
type Scanner struct{}

func (Scanner) ID() string              { return "code.secrets" }
func (Scanner) Category() core.Category { return core.CategoryCode }
func (Scanner) Mode() core.Mode         { return core.ModePassive }
func (Scanner) Description() string     { return "A credential or key is committed to the source tree" }
func (Scanner) OWASP() []string         { return []string{"A05:2021"} }
func (Scanner) ASVS() []string          { return []string{"V6.4.1", "V14.3.2"} }

func (Scanner) Run(_ context.Context, t core.Target) ([]core.Finding, error) {
	root := repo.Base(t.Repo)
	if root == "" {
		return nil, nil // nothing to scan without a repo
	}
	var out []core.Finding
	seen := map[string]bool{} // rule|file|line — one finding per spot
	err := repo.Walk(root, func(f repo.File) error {
		lines := repo.Lines(f.Data)
		for i, line := range lines {
			if len(line) > 4000 {
				continue // skip minified / data lines
			}
			// Honour a suppression on this line or the one directly above it.
			if suppress.MatchString(line) || (i > 0 && suppress.MatchString(lines[i-1])) {
				continue
			}
			// A weak-pattern "secret" in a test file or doc is a fixture, not a
			// leak — a test that signs a token must contain a signing key. Skip
			// those files for the weak rules; strong patterns (real cloud keys)
			// still report even here.
			weakSkip := testOrDoc.MatchString(f.Rel)
			for _, r := range rules {
				if weakSkip && !strongRules[r.id] {
					continue
				}
				m := r.re.FindString(line)
				if m == "" || placeholder.MatchString(line) {
					continue
				}
				// A generic-secret whose value is a URL path/route (RESET_PASSWORD:
				// "/api/auth/reset-password") or an env-var name (SecretEnv:
				// "UNUSED_SECRET") is a reference, not a credential.
				if r.id == "generic-secret" {
					v := quotedValue(m)
					if routeOrPath.MatchString(v) || envVarName.MatchString(v) {
						continue
					}
				}
				key := r.id + "|" + f.Rel + "|" + itoa(i+1)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, finding(t, f.Rel, i+1, r, m, line))
			}
		}
		return nil
	})
	return out, err
}

func finding(t core.Target, file string, line int, r rule, match, raw string) core.Finding {
	return core.Finding{
		Title:      r.desc + " in " + file,
		Category:   core.CategoryCode,
		Severity:   r.sev,
		Confidence: core.ConfidenceLikely, // may be a revoked or test value
		Asset:      core.Asset{Kind: core.AssetFile, Value: file + ":" + itoa(line), File: file, Line: line, Criticality: t.Criticality},
		Location:   r.id,
		Evidence:   core.Evidence{ConfigLine: maskLine(raw, match), Matched: mask(match), Redacted: true},
		Tags:       []string{core.TagExposedSecret},
		CWE:        []string{"CWE-798"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What: "A secret is committed in the source tree, where anyone with repo access (and anyone it is later shared or leaked to) can read it.",
			Why:  "Committed secrets live forever in git history even if deleted, and are a leading cause of breaches. Treat any committed secret as compromised.",
			How: []core.Fix{
				{Stack: "generic", Language: "text", Code: "1. Rotate the credential now (assume it is compromised).\n2. Remove it from the code; load it from an environment variable or a secret manager.\n3. Purge it from git history (git filter-repo) and add the path to .gitignore."},
			},
			Effort:     core.EffortM,
			References: []string{"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password", "https://cwe.mitre.org/data/definitions/798.html"},
		},
	}
}

// quotedValue returns the contents of the first quoted string in a match, which
// for the generic-secret rule is the assigned value.
func quotedValue(m string) string {
	i := strings.IndexAny(m, `"'`)
	if i < 0 {
		return ""
	}
	q := m[i]
	j := strings.IndexByte(m[i+1:], q)
	if j < 0 {
		return ""
	}
	return m[i+1 : i+1+j]
}

// mask shows only the shape of a secret, never its value.
func mask(s string) string {
	if len(s) <= 6 {
		return strings.Repeat("*", len(s))
	}
	return s[:3] + strings.Repeat("*", 8) + "(" + itoa(len(s)) + " chars)"
}

// maskLine replaces the matched secret within its line with the mask.
func maskLine(line, match string) string {
	line = strings.TrimSpace(line)
	if len(line) > 200 {
		line = line[:200]
	}
	return strings.Replace(line, match, mask(match), 1)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
