package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestMarkdownExport(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, []Result{build()}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"# Scout security report",
		"## https://shop.example.com",
		"**Grade F**",
		"| Severity | Category | Title | Asset |",
		"CRITICAL", // severity upper-cased
		"Injection in search",
		"**What:** what Injection in search",
		"CWE-693",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	// Worst-first ordering: the critical finding appears before the low one.
	if strings.Index(out, "Injection in search") > strings.Index(out, "nosniff missing") {
		t.Error("findings not sorted worst-first")
	}
}

func TestTextExport(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, []Result{build()}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"SCOUT SECURITY REPORT", "[CRITICAL] Injection in search", "What: what"} {
		if !strings.Contains(out, want) {
			t.Errorf("text missing %q", want)
		}
	}
	if strings.Contains(out, "|") || strings.Contains(out, "```") {
		t.Error("text export should have no markdown syntax")
	}
}
