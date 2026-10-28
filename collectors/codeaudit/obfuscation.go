package codeaudit

import (
	"context"
	"regexp"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/repo"
	"github.com/MUKE-coder/scout/core"
)

// Obfuscation flags two supply-chain tampering signals that show up when a repo's
// config or source is compromised: install/CI scripts that fetch and execute
// remote code, and obfuscated code that hides a payload (the pattern behind the
// event-stream, xz and many npm/pip backdoors). It reads files only.
type Obfuscation struct{}

func (Obfuscation) ID() string              { return "code.obfuscation" }
func (Obfuscation) Category() core.Category { return core.CategoryCode }
func (Obfuscation) Mode() core.Mode         { return core.ModePassive }
func (Obfuscation) Description() string {
	return "A config/script fetches and runs remote code, or source contains obfuscated payloads (possible supply-chain tamper)"
}
func (Obfuscation) OWASP() []string { return []string{"A08:2021"} }
func (Obfuscation) ASVS() []string  { return []string{"V10.3.2"} }

type obfRule struct {
	re   *regexp.Regexp
	note string
	sev  core.Severity
}

var (
	// A remote fetch piped straight into an interpreter — the classic
	// install/CI backdoor: curl https://x | sh.
	remoteExecRule = obfRule{
		re:   regexp.MustCompile(`(?i)(curl|wget|fetch|iwr|invoke-webrequest)\b[^|&;` + "`" + `]*[|]\s*(sh|bash|zsh|python[0-9.]*|node|perl|ruby|powershell|pwsh)\b`),
		note: "remote content is fetched and piped to an interpreter",
		sev:  core.SeverityHigh,
	}
	// eval "$(curl ...)" and friends.
	evalCurlRule = obfRule{
		re:   regexp.MustCompile(`(?i)(eval|exec|source)\s+["']?\$\((curl|wget|fetch)`),
		note: "remote content is fetched and evaluated",
		sev:  core.SeverityHigh,
	}
	// eval/Function over decoded data — a payload hidden behind base64/hex.
	evalDecodeRule = obfRule{
		re:   regexp.MustCompile(`(?i)(eval|new\s+Function|Function|setTimeout|setInterval)\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent|globalThis\[|window\[)`),
		note: "code is decoded at runtime and executed (eval over atob/Buffer.from/…)",
		sev:  core.SeverityHigh,
	}
	// Long String.fromCharCode(...) chains build a hidden string.
	fromCharCodeRule = obfRule{
		re:   regexp.MustCompile(`(?i)String\.fromCharCode\s*\(\s*(0x[0-9a-f]+|\d+)\s*(,\s*(0x[0-9a-f]+|\d+)\s*){9,}\)`),
		note: "a string is assembled from character codes (obfuscation)",
		sev:  core.SeverityMedium,
	}
	// Dense hex-escape strings hide a payload.
	hexBlobRule = obfRule{
		re:   regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){16,}`),
		note: "a dense hex-escaped string (obfuscation)",
		sev:  core.SeverityMedium,
	}
)

func (c Obfuscation) Run(_ context.Context, t core.Target) ([]core.Finding, error) {
	root := repo.Base(t.Repo)
	if root == "" {
		return nil, nil
	}
	var out []core.Finding
	seen := map[string]bool{}
	err := repo.Walk(root, func(f repo.File) error {
		rules := obfRulesFor(f.Rel)
		if len(rules) == 0 {
			return nil
		}
		lines := repo.Lines(f.Data)
		for i, line := range lines {
			if len(line) > 8000 {
				continue
			}
			// Skip full-line comments only. We must NOT strip mid-line "//", or a
			// URL like https://… inside a "curl https://x | sh" command would be
			// truncated and the payload missed.
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			if suppress.MatchString(line) || (i > 0 && suppress.MatchString(lines[i-1])) {
				continue
			}
			for _, r := range rules {
				m := r.re.FindString(line)
				if m == "" {
					continue
				}
				key := f.Rel + "|" + itoa(i+1)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, obfFinding(t, f.Rel, i+1, r, line, m))
				break
			}
		}
		return nil
	})
	return out, err
}

// obfRulesFor returns the rules that apply to a file: fetch-and-exec rules for
// scripts/manifests/CI, obfuscation rules for JS/TS/JSON source.
func obfRulesFor(rel string) []obfRule {
	low := strings.ToLower(rel)
	name := base(low)
	scriptish := strings.HasSuffix(low, ".sh") || strings.HasSuffix(low, ".bash") || strings.HasSuffix(low, ".ps1") ||
		strings.HasPrefix(name, "dockerfile") || strings.HasPrefix(name, "makefile") || strings.HasSuffix(low, ".mk") ||
		name == "package.json" || name == ".npmrc" || name == ".yarnrc" ||
		strings.Contains(low, ".husky/") ||
		(strings.Contains(low, ".github/workflows/") && (strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".yaml")))
	code := hasExt(low, []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".vue", ".svelte"})

	var rules []obfRule
	if scriptish {
		rules = append(rules, remoteExecRule, evalCurlRule)
	}
	if code {
		rules = append(rules, evalDecodeRule, fromCharCodeRule, hexBlobRule)
	}
	return rules
}

func obfFinding(t core.Target, file string, line int, r obfRule, raw, match string) core.Finding {
	return core.Finding{
		Title:      "Possible supply-chain tamper in " + file,
		Category:   core.CategoryCode,
		Severity:   r.sev,
		Confidence: core.ConfidenceLikely,
		Asset:      core.Asset{Kind: core.AssetFile, Value: file + ":" + itoa(line), File: file, Line: line, Criticality: t.Criticality},
		Location:   "code.obfuscation",
		Evidence:   core.Evidence{ConfigLine: strings.TrimSpace(trunc(raw)), Matched: match, Notes: r.note},
		CWE:        []string{"CWE-506"}, // embedded malicious code
		OWASP:      []string{"A08:2021"},
		Remediation: core.Remediation{
			What:       "A file " + r.note + " — a pattern seen when a repository's config or dependencies are compromised to run attacker code on install, in CI, or at runtime.",
			Why:        "Fetch-and-run and obfuscated payloads are how supply-chain backdoors (event-stream, xz, malicious npm/pip packages) execute. Treat an unexpected match as a potential compromise.",
			How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Review this line and its git history (who added it, in which commit). Never pipe remote content into a shell; pin and verify what install/CI steps run. If it is unexpected, rotate credentials and audit the dependency that introduced it."}},
			Effort:     core.EffortM,
			References: []string{"https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/", "https://cwe.mitre.org/data/definitions/506.html"},
		},
	}
}
