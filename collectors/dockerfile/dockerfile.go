// Package dockerfile lints Dockerfiles in a target's source tree for common
// security misconfigurations: running as root, unpinned base images, remote
// ADD, and secrets baked into ENV/ARG. It reads files only — passive, no
// network, no container is built or run.
package dockerfile

import (
	"context"
	"regexp"
	"strings"

	"github.com/MUKE-coder/scout/collectors/internal/repo"
	"github.com/MUKE-coder/scout/core"
)

func init() { core.Register(Lint{}) }

// Lint flags Dockerfile security misconfigurations.
type Lint struct{}

func (Lint) ID() string              { return "code.dockerfile" }
func (Lint) Category() core.Category { return core.CategoryConfig }
func (Lint) Mode() core.Mode         { return core.ModePassive }
func (Lint) Description() string     { return "A Dockerfile has a security misconfiguration" }
func (Lint) OWASP() []string         { return []string{"A05:2021"} }

var (
	reFrom      = regexp.MustCompile(`(?i)^\s*FROM\s+(\S+)`)
	reUser      = regexp.MustCompile(`(?i)^\s*USER\s+(\S+)`)
	reAddRemote = regexp.MustCompile(`(?i)^\s*ADD\s+https?://`)
	reEnvSecret = regexp.MustCompile(`(?i)^\s*(?:ENV|ARG)\s+.*(password|passwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)\s*[=\s]\s*\S`)
	reEnvPlace  = regexp.MustCompile(`(?i)(example|changeme|your[_-]?|placeholder|dummy|\$\{|<[a-z])`)
)

func isDockerfile(rel string) bool {
	base := rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		base = rel[i+1:]
	}
	return base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".Dockerfile") || strings.EqualFold(base, "containerfile")
}

func (Lint) Run(_ context.Context, t core.Target) ([]core.Finding, error) {
	root := repo.Base(t.Repo)
	if root == "" {
		return nil, nil
	}
	var out []core.Finding
	err := repo.Walk(root, func(f repo.File) error {
		if !isDockerfile(f.Rel) {
			return nil
		}
		out = append(out, lintFile(t, f)...)
		return nil
	})
	return out, err
}

func lintFile(t core.Target, f repo.File) []core.Finding {
	var out []core.Finding
	lines := repo.Lines(f.Data)
	lastFromLine, lastFromUnpinned := 0, false
	sawUser := false // any USER instruction in the current build stage

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case reFrom.MatchString(line):
			img := reFrom.FindStringSubmatch(line)[1]
			lastFromLine = i + 1
			lastFromUnpinned = unpinned(img)
			sawUser = false // USER applies per build stage
		case reUser.MatchString(line):
			sawUser = true
			if u := reUser.FindStringSubmatch(line)[1]; strings.EqualFold(u, "root") || u == "0" {
				out = append(out, df(t, f, i+1, "docker.user-root", core.SeverityMedium,
					"Container runs as root (USER root)",
					"Running as root means a container escape or app compromise has root in the container.",
					"Add a non-root user: `RUN adduser -D app` then `USER app`.", line))
			}
		case reAddRemote.MatchString(line):
			out = append(out, df(t, f, i+1, "docker.add-remote", core.SeverityLow,
				"ADD fetches a remote URL",
				"ADD from a URL is unverified and can change under you; it also disables build-cache safety.",
				"Use a pinned `curl`/`wget` with a checksum, or COPY a vendored copy, instead of `ADD https://...`.", line))
		case reEnvSecret.MatchString(line) && !reEnvPlace.MatchString(line):
			out = append(out, df(t, f, i+1, "docker.env-secret", core.SeverityHigh,
				"Secret baked into an image layer (ENV/ARG)",
				"Values in ENV/ARG are stored in the image and visible via `docker history` to anyone with the image.",
				"Pass secrets at runtime (`--env-file`, a secret manager, or BuildKit `--mount=type=secret`), never in ENV/ARG.", line))
		}
	}
	if lastFromLine > 0 && !sawUser {
		out = append(out, df(t, f, lastFromLine, "docker.no-user", core.SeverityMedium,
			"Image does not drop root (no USER instruction)",
			"Without a USER instruction the container runs as root by default.",
			"Add a non-root `USER` before the entrypoint in the final stage.", "FROM ..."))
	}
	if lastFromUnpinned {
		out = append(out, df(t, f, lastFromLine, "docker.unpinned-base", core.SeverityLow,
			"Base image is unpinned (uses :latest or no tag)",
			"An unpinned base image makes builds non-reproducible and silently pulls in changes.",
			"Pin the base image to a specific tag and ideally a digest (`image:1.2.3@sha256:...`).", "FROM ..."))
	}
	return out
}

func unpinned(img string) bool {
	if strings.Contains(img, "@sha256:") {
		return false
	}
	name, tag, has := strings.Cut(img, ":")
	_ = name
	return !has || strings.EqualFold(tag, "latest")
}

func df(t core.Target, f repo.File, line int, id string, sev core.Severity, title, why, how, raw string) core.Finding {
	if len(raw) > 200 {
		raw = raw[:200]
	}
	return core.Finding{
		Title:      title + " in " + f.Rel,
		Category:   core.CategoryConfig,
		Severity:   sev,
		Confidence: core.ConfidenceConfirmed,
		Asset:      core.Asset{Kind: core.AssetFile, Value: f.Rel + ":" + itoa(line), File: f.Rel, Line: line, Criticality: t.Criticality},
		Location:   id,
		Evidence:   core.Evidence{ConfigLine: strings.TrimSpace(raw)},
		CWE:        []string{"CWE-250"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What:       title + ".",
			Why:        why,
			How:        []core.Fix{{Stack: "dockerfile", Language: "dockerfile", Code: how}},
			Effort:     core.EffortS,
			References: []string{"https://docs.docker.com/develop/security-best-practices/"},
		},
	}
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
