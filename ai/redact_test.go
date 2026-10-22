package ai

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func TestTextRedaction(t *testing.T) {
	in := `Contact admin@shop.example.com from 203.0.113.7 or 2001:db8::1:2:3; ` +
		`see https://user:pw@shop.example.com/reset?token=abc123#frag; ` +
		`Authorization: Bearer abcdefgh12345678; password=hunter2; api_key: "sk_live_1234"; ` +
		`jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig; blob ` + strings.Repeat("A1", 20) + `; host shop.example.com`
	out := Text(in, "shop.example.com")
	for _, leaked := range []string{
		"admin@", "203.0.113.7", "2001:db8", "user:pw", "token=abc123", "#frag",
		"abcdefgh12345678", "hunter2", "sk_live_1234", "eyJhbGci", strings.Repeat("A1", 20), "shop.example.com",
	} {
		if strings.Contains(out, leaked) {
			t.Errorf("leaked %q in: %s", leaked, out)
		}
	}
	for _, kept := range []string{"https://<host>/reset", "<email>", "<ip>", "<jwt>", "password=<redacted>"} {
		if !strings.Contains(out, kept) {
			t.Errorf("expected %q in: %s", kept, out)
		}
	}
}

func TestFindingOmitsEvidence(t *testing.T) {
	f := core.Finding{
		CheckID: "headers.csp", Title: "CSP missing on shop.example.com", Category: core.CategoryHeaders,
		Severity: core.SeverityMedium, Confidence: core.ConfidenceConfirmed,
		Asset: core.Asset{Kind: core.AssetURL, Value: "https://shop.example.com/account?id=42", Host: "shop.example.com"},
		Evidence: core.Evidence{
			Request:  "GET /account?id=42 HTTP/1.1\r\nCookie: session=SECRET-COOKIE",
			Response: "HTTP/1.1 200 OK\r\nSet-Cookie: sid=SECRET-SID\r\n\r\n<html>private</html>",
			Matched:  "SECRET-PAYLOAD",
		},
		CWE:         []string{"CWE-693"},
		Remediation: core.Remediation{What: "No CSP.", Why: "XSS risk.", Effort: core.EffortM, How: []core.Fix{{Stack: "nginx", Code: "add_header ..."}}},
	}
	r := Finding(f)
	b, _ := json.Marshal(r)
	body := string(b)
	for _, leaked := range []string{"SECRET-COOKIE", "SECRET-SID", "SECRET-PAYLOAD", "private", "id=42", "shop.example.com", "add_header"} {
		if strings.Contains(body, leaked) {
			t.Errorf("redacted finding leaked %q: %s", leaked, body)
		}
	}
	if r.Asset != "https://<host>/account" || r.Title != "CSP missing on <host>" || r.FixStacks[0] != "nginx" || r.CWE[0] != "CWE-693" {
		t.Fatalf("redacted = %+v", r)
	}
}
