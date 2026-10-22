package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/scoring"
)

// fakeGateway records the request and replies like the Chat Completions API.
func fakeGateway(t *testing.T, status int, reply string) (*httptest.Server, *chatRequest, *http.Header) {
	t.Helper()
	var got chatRequest
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		hdr = r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &hdr
}

func secretFinding() core.Finding {
	f := core.Finding{
		CheckID: "headers.csp", Title: "CSP missing", Category: core.CategoryHeaders, Severity: core.SeverityMedium,
		Confidence: core.ConfidenceConfirmed, Status: core.StatusOpen,
		Asset:       core.Asset{Kind: core.AssetURL, Value: "https://shop.example.com/?sid=SECRET", Host: "shop.example.com"},
		Evidence:    core.Evidence{Response: "Set-Cookie: sid=SECRET-SID"},
		Remediation: core.Remediation{What: "No CSP.", Effort: core.EffortM},
	}
	f.Normalize()
	return f
}

func TestExplainSendsOnlyRedactedData(t *testing.T) {
	srv, got, hdr := fakeGateway(t, http.StatusOK, `{"choices":[{"message":{"role":"assistant","content":"  Add a CSP.  "}}]}`)
	c := &Client{BaseURL: srv.URL + "/v1", APIKey: "vck_test", Model: "openai/gpt-x"}
	ans, err := c.Explain(context.Background(), secretFinding(), []string{"nginx"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.Text != "Add a CSP." || ans.Model != "openai/gpt-x" || ans.Sent == nil {
		t.Fatalf("answer = %+v", ans)
	}
	if hdr.Get("Authorization") != "Bearer vck_test" || got.Model != "openai/gpt-x" || len(got.Messages) != 2 {
		t.Fatalf("request: auth=%q model=%q messages=%d", hdr.Get("Authorization"), got.Model, len(got.Messages))
	}
	sent := got.Messages[1].Content
	for _, leaked := range []string{"SECRET", "shop.example.com"} {
		if strings.Contains(sent, leaked) {
			t.Fatalf("gateway received %q:\n%s", leaked, sent)
		}
	}
	if !strings.Contains(sent, `"detected_stacks"`) || !strings.Contains(sent, "nginx") {
		t.Fatalf("stack context missing:\n%s", sent)
	}
}

func TestSummarize(t *testing.T) {
	srv, got, _ := fakeGateway(t, http.StatusOK, `{"choices":[{"message":{"content":"Posture is fair."}}]}`)
	c := &Client{BaseURL: srv.URL + "/v1", APIKey: "k"}
	scans := []core.ScanResult{{Target: core.Target{Name: "shop", URL: "https://shop.example.com", Environment: core.EnvProd},
		Findings: []core.Finding{secretFinding()}, Assessed: []core.Category{core.CategoryHeaders}}}
	ans, err := c.Summarize(context.Background(), scans, scoring.Options{})
	if err != nil || ans.Text != "Posture is fair." || ans.Model != DefaultModel {
		t.Fatalf("answer = %+v, %v", ans, err)
	}
	sent := got.Messages[1].Content
	if strings.Contains(sent, "shop.example.com") || strings.Contains(sent, "SECRET") || !strings.Contains(sent, `"target": "shop"`) {
		t.Fatalf("summary payload:\n%s", sent)
	}
}

func TestGatewayErrors(t *testing.T) {
	if _, err := (&Client{}).Explain(context.Background(), secretFinding(), nil); err != ErrDisabled {
		t.Fatalf("unconfigured client: %v", err)
	}
	srv, _, _ := fakeGateway(t, http.StatusUnauthorized, `{"error":{"message":"Invalid API key"}}`)
	_, err := (&Client{BaseURL: srv.URL + "/v1", APIKey: "bad"}).Explain(context.Background(), secretFinding(), nil)
	if err == nil || !strings.Contains(err.Error(), "Invalid API key") {
		t.Fatalf("error = %v", err)
	}
	empty, _, _ := fakeGateway(t, http.StatusOK, `{"choices":[]}`)
	if _, err := (&Client{BaseURL: empty.URL + "/v1", APIKey: "k"}).Explain(context.Background(), secretFinding(), nil); err == nil {
		t.Fatal("empty choices should be an error")
	}
}
