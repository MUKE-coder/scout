package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/remediation"
	"github.com/MUKE-coder/scout/scoring"
)

func TestHTMLReport(t *testing.T) {
	r := build()
	// Text from a scanned site must be escaped, never rendered as markup.
	r.Scan.Findings[0].Title = `<script>alert("x")</script> nosniff missing`
	r.Scan.Findings[0].Evidence.Matched = `<img src=x onerror=alert(1)>`
	r.Scan.Findings[0].Remediation.How = remediation.SetHeader("X-Content-Type-Options", "nosniff")
	r.Scan.Findings[0].Evidence.Response = "HTTP/1.1 200 OK\r\nServer: nginx\r\n"
	accepted := r.Scan.Findings[1]
	accepted.Fingerprint, accepted.Title, accepted.Status = "acc", "Accepted thing", core.StatusAcceptedRisk
	r.Scan.Findings = append(r.Scan.Findings, accepted)

	var buf bytes.Buffer
	gen := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	if err := HTML(&buf, []Result{r}, HTMLOptions{Version: "1.2.3", Generated: gen}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"<title>Scout security report</title>",
		"Generated 2026-10-22 12:00 UTC by Scout 1.2.3",
		"https://shop.example.com",
		"capped at F", // cap reason shown
		"Fix next",
		"Critical (1)",
		"&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;",
		"&lt;img src=x onerror=alert(1)&gt;",
		"Fix (nginx)", // detected stack's fix selected
		"cwe.mitre.org/data/definitions/693.html",
		"@media print",
	} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Contains(out, "<script>alert") || strings.Contains(out, "<img src=x") {
		t.Fatal("scanned text was not escaped")
	}
	if strings.Contains(out, "Fix (gin)") {
		t.Error("only the detected stack's fix should be shown")
	}
	if strings.Contains(out, "Accepted thing") {
		t.Error("accepted-risk findings should be excluded")
	}
}

func TestHTMLReportNothingAssessed(t *testing.T) {
	s := sample()
	s.Findings, s.Assessed = nil, []core.Category{}
	var buf bytes.Buffer
	if err := HTML(&buf, []Result{Build(s, scoring.Options{})}, HTMLOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No checks ran") {
		t.Fatal("an unassessed scan must not look like a pass")
	}
}
