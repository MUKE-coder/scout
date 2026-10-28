// Package templates runs declarative YAML detection templates against a live
// target — a safe, Nuclei-compatible subset. Detections become data: a new CVE,
// exposed panel or misconfiguration check is a YAML file, not Go code, and users
// can drop their own into a templates directory without recompiling.
//
// Safety (Scout stays detective, never weaponized): only GET/HEAD requests with
// no body run. Templates that use raw requests, request bodies, fuzzing payloads
// or variable/interpolation expressions in the path (anything beyond {{BaseURL}}
// and {{Hostname}}) are skipped — Scout will not fire an exploit from a template.
package templates

import (
	"context"
	"embed"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/MUKE-coder/scout/collectors/internal/httpx"
	"github.com/MUKE-coder/scout/core"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// UserDir is an extra directory of user templates, loaded alongside the built-in
// ones. Set by the CLI (--templates) or the SCOUT_TEMPLATES env var.
var UserDir = os.Getenv("SCOUT_TEMPLATES")

func init() { core.Register(Check{}) }

// --- template schema (Nuclei subset) ---------------------------------------

type Template struct {
	ID   string    `yaml:"id"`
	Info Info      `yaml:"info"`
	HTTP []Request `yaml:"http"`
	// Nuclei v1 used "requests"; accept it too.
	Requests []Request `yaml:"requests"`
}

type Info struct {
	Name           string         `yaml:"name"`
	Severity       string         `yaml:"severity"`
	Description    string         `yaml:"description"`
	Remediation    string         `yaml:"remediation"`
	Reference      flexStrings    `yaml:"reference"`
	Tags           string         `yaml:"tags"`
	Classification Classification `yaml:"classification"`
}

type Classification struct {
	CVE   string      `yaml:"cve-id"`
	CWE   flexStrings `yaml:"cwe-id"`
	OWASP flexStrings `yaml:"owasp"`
}

type Request struct {
	Method       string            `yaml:"method"`
	Path         []string          `yaml:"path"`
	Headers      map[string]string `yaml:"headers"`
	Body         string            `yaml:"body"`
	Raw          []string          `yaml:"raw"`
	MatchersCond string            `yaml:"matchers-condition"`
	Matchers     []Matcher         `yaml:"matchers"`
}

type Matcher struct {
	Type      string      `yaml:"type"`
	Words     flexStrings `yaml:"words"`
	Regex     flexStrings `yaml:"regex"`
	Status    []int       `yaml:"status"`
	Part      string      `yaml:"part"`
	Condition string      `yaml:"condition"`
	Negative  bool        `yaml:"negative"`
}

// flexStrings decodes a YAML value that may be a single scalar or a sequence.
type flexStrings []string

func (f *flexStrings) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		*f = []string{value.Value}
		return nil
	}
	var s []string
	if err := value.Decode(&s); err != nil {
		return err
	}
	*f = s
	return nil
}

// --- loading ---------------------------------------------------------------

var (
	loadOnce sync.Once
	loaded   []Template
)

func all() []Template {
	loadOnce.Do(func() {
		loaded = loadBuiltin()
		if UserDir != "" {
			loaded = append(loaded, loadDir(os.DirFS(UserDir))...)
		}
	})
	return loaded
}

func loadBuiltin() []Template {
	sub, err := fs.Sub(builtinFS, "builtin")
	if err != nil {
		return nil
	}
	return loadDir(sub)
}

func loadDir(fsys fs.FS) []Template {
	var out []Template
	_ = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		b, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil
		}
		var t Template
		if yaml.Unmarshal(b, &t) == nil && t.ID != "" {
			out = append(out, t)
		}
		return nil
	})
	return out
}

// requests returns the template's HTTP requests (either key).
func (t Template) requests() []Request {
	if len(t.HTTP) > 0 {
		return t.HTTP
	}
	return t.Requests
}

// safe reports whether a request is a benign GET/HEAD detection we will run.
func (r Request) safe() bool {
	m := strings.ToUpper(strings.TrimSpace(r.Method))
	if m != "" && m != http.MethodGet && m != http.MethodHead {
		return false
	}
	if r.Body != "" || len(r.Raw) > 0 || len(r.Path) == 0 {
		return false
	}
	return true
}

// --- the check -------------------------------------------------------------

type Check struct{}

func (Check) ID() string              { return "app.template" }
func (Check) Category() core.Category { return core.CategoryApp }
func (Check) Mode() core.Mode         { return core.ModeSafe }
func (Check) Description() string {
	return "A declarative detection template matched (exposed panel, misconfiguration, known CVE signature)"
}
func (Check) OWASP() []string { return []string{"A05:2021"} }

func (c Check) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.URL == "" {
		return nil, nil
	}
	var out []core.Finding
	for _, tpl := range all() {
		for _, req := range tpl.requests() {
			if !req.safe() {
				continue
			}
			for _, raw := range req.Path {
				u := expand(raw, t)
				if u == "" || strings.Contains(u, "{{") {
					continue // unresolved variable/payload — skip for safety
				}
				page, err := httpx.Do(ctx, method(req), u, header(req.Headers))
				if err != nil || page == nil {
					continue
				}
				if matches(req, page) {
					out = append(out, finding(t, tpl, page))
					break // one finding per template is enough
				}
			}
		}
	}
	return out, nil
}

func method(r Request) string {
	if m := strings.ToUpper(strings.TrimSpace(r.Method)); m != "" {
		return m
	}
	return http.MethodGet
}

func header(h map[string]string) http.Header {
	if len(h) == 0 {
		return nil
	}
	out := http.Header{}
	for k, v := range h {
		out.Set(k, v)
	}
	return out
}

// expand resolves a template path to an absolute URL, substituting the two safe
// placeholders. Returns "" if it cannot be resolved.
func expand(raw string, t core.Target) string {
	s := strings.TrimSpace(raw)
	base := strings.TrimRight(t.URL, "/")
	host := t.Host()
	s = strings.ReplaceAll(s, "{{BaseURL}}", base)
	s = strings.ReplaceAll(s, "{{RootURL}}", base)
	s = strings.ReplaceAll(s, "{{Hostname}}", host)
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s
	}
	if strings.HasPrefix(s, "/") {
		if u, err := httpx.Resolve(t, s); err == nil {
			return u.String()
		}
	}
	return ""
}

// --- matching --------------------------------------------------------------

func matches(r Request, p *httpx.Page) bool {
	if len(r.Matchers) == 0 {
		return false
	}
	orMode := strings.EqualFold(r.MatchersCond, "or")
	for _, m := range r.Matchers {
		ok := matchOne(m, p)
		if m.Negative {
			ok = !ok
		}
		if orMode && ok {
			return true
		}
		if !orMode && !ok {
			return false
		}
	}
	return !orMode // AND: all passed; OR: none passed
}

func matchOne(m Matcher, p *httpx.Page) bool {
	switch strings.ToLower(m.Type) {
	case "status":
		for _, s := range m.Status {
			if p.Status == s {
				return true
			}
		}
		return false
	case "word":
		hay := part(m.Part, p)
		return wordsMatch(m.Words, hay, strings.EqualFold(m.Condition, "and"))
	case "regex":
		hay := part(m.Part, p)
		return regexMatch(m.Regex, hay, strings.EqualFold(m.Condition, "and"))
	default:
		return false
	}
}

func part(which string, p *httpx.Page) string {
	switch strings.ToLower(which) {
	case "header":
		return p.Response // dumped headers+status
	case "all", "raw":
		return p.Response + "\n" + string(p.Body)
	default: // body
		return string(p.Body)
	}
}

func wordsMatch(words flexStrings, hay string, and bool) bool {
	if len(words) == 0 {
		return false
	}
	low := strings.ToLower(hay)
	for _, w := range words {
		has := strings.Contains(low, strings.ToLower(w))
		if and && !has {
			return false
		}
		if !and && has {
			return true
		}
	}
	return and
}

func regexMatch(res flexStrings, hay string, and bool) bool {
	if len(res) == 0 {
		return false
	}
	for _, rx := range res {
		re, err := regexp.Compile(rx)
		has := err == nil && re.MatchString(hay)
		if and && !has {
			return false
		}
		if !and && has {
			return true
		}
	}
	return and
}

// --- finding ---------------------------------------------------------------

func finding(t core.Target, tpl Template, p *httpx.Page) core.Finding {
	title := tpl.Info.Name
	if title == "" {
		title = tpl.ID
	}
	refs := []string(tpl.Info.Reference)
	remediation := tpl.Info.Remediation
	if remediation == "" {
		remediation = "Review the matched endpoint; restrict or remove public access if it exposes internal data or functionality."
	}
	return core.Finding{
		Title:      title,
		Category:   core.CategoryApp,
		Severity:   severity(tpl.Info.Severity),
		Confidence: core.ConfidenceLikely,
		Asset:      httpx.Asset(t, p.URL),
		Location:   tpl.ID,
		Evidence:   core.Evidence{Request: p.Request, Response: redact(p.Response), Notes: "matched template " + tpl.ID},
		CWE:        cwes(tpl.Info.Classification.CWE),
		OWASP:      owasp(tpl.Info.Classification.OWASP),
		Remediation: core.Remediation{
			What:       descOr(tpl.Info.Description, title),
			Why:        "This was flagged by a detection template (" + tpl.ID + "); verify it against your intended exposure.",
			How:        []core.Fix{{Stack: "generic", Language: "text", Code: remediation}},
			Effort:     core.EffortM,
			References: refs,
		},
	}
}

func descOr(desc, title string) string {
	if strings.TrimSpace(desc) != "" {
		return strings.TrimSpace(desc)
	}
	return title + " was detected."
}

func severity(s string) core.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return core.SeverityCritical
	case "high":
		return core.SeverityHigh
	case "medium":
		return core.SeverityMedium
	case "low":
		return core.SeverityLow
	default:
		return core.SeverityInfo
	}
}

func cwes(c flexStrings) []string {
	out := make([]string, 0, len(c))
	for _, v := range c {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v != "" {
			if !strings.HasPrefix(v, "CWE-") {
				v = "CWE-" + strings.TrimPrefix(v, "CWE")
			}
			out = append(out, v)
		}
	}
	return out
}

func owasp(o flexStrings) []string {
	if len(o) == 0 {
		return []string{"A05:2021"}
	}
	return []string(o)
}

// redact trims an over-long response dump kept as evidence.
func redact(s string) string {
	const max = 2000
	if len(s) > max {
		return s[:max] + "\n… (truncated)"
	}
	return s
}
