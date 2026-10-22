package remediation

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func TestDetectStacks(t *testing.T) {
	cases := []struct {
		resp string
		gin  bool
		want string
	}{
		{"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n", false, "nginx"},
		{"HTTP/1.1 200 OK\r\nServer: Caddy\r\n", false, "caddy"},
		{"HTTP/1.1 200 OK\r\nX-Powered-By: Next.js\r\nServer: nginx\r\n", false, "nextjs,nginx"},
		{"HTTP/1.1 200 OK\r\n", true, "gin"},
		{"HTTP/1.1 200 OK\r\nServer: Apache\r\n", false, ""},
	}
	for _, c := range cases {
		if got := strings.Join(DetectStacks(c.resp, c.gin), ","); got != c.want {
			t.Errorf("DetectStacks(%q, %v) = %q, want %q", c.resp, c.gin, got, c.want)
		}
	}
}

func TestSelectFixes(t *testing.T) {
	all := SetHeader("X-Content-Type-Options", "nosniff")
	if got := SelectFixes(all, []string{Nginx}); len(got) != 1 || got[0].Stack != Nginx {
		t.Fatalf("nginx only: %+v", got)
	}
	if got := SelectFixes(all, nil); len(got) != len(all) {
		t.Fatal("unknown stack should show every fix")
	}
	if got := SelectFixes(all, []string{"apache"}); len(got) != len(all) {
		t.Fatal("unmatched stack should fall back to every fix")
	}
	withGeneric := append(all, core.Fix{Stack: Generic, Code: "x"})
	if got := SelectFixes(withGeneric, []string{Caddy}); len(got) != 2 || got[1].Stack != Generic {
		t.Fatalf("generic fixes should always be included: %+v", got)
	}
}

func TestRender(t *testing.T) {
	f := core.Finding{
		Title: "X-Content-Type-Options: nosniff is missing", Severity: core.SeverityLow,
		Confidence: core.ConfidenceConfirmed, Asset: core.Asset{Value: "https://example.com/"},
		CWE: []string{"CWE-693"}, OWASP: []string{"A05:2021"},
		Remediation: core.Remediation{
			What: "Responses do not send nosniff.", Why: "Browsers may sniff types.",
			How: SetHeader("X-Content-Type-Options", "nosniff"), Effort: core.EffortS,
			References: []string{"https://developer.mozilla.org/"},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, f, []string{Nginx}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"## X-Content-Type-Options: nosniff is missing",
		"**Effort:** small",
		"### Why it matters",
		"**Nginx**",
		`add_header X-Content-Type-Options "nosniff" always;`,
		"https://cwe.mitre.org/data/definitions/693.html",
		"OWASP A05:2021",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "**Gin**") {
		t.Error("render should only show the detected stack's fix")
	}
}
