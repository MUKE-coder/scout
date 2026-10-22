package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/ai"
	"github.com/MUKE-coder/scout/core"
)

func TestAIDisabledByDefault(t *testing.T) {
	f := newFixture(t)
	if st := decode[map[string]any](t, f.do(http.MethodGet, "/scout/api/ai", "")); st["enabled"] != false {
		t.Fatalf("status = %v", st)
	}
	if w := f.do(http.MethodPost, "/scout/api/ai/summary", ""); w.Code != http.StatusNotFound {
		t.Fatalf("summary without AI: %d", w.Code)
	}
}

func TestAIExplainAndSummary(t *testing.T) {
	var sent []string
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sent = append(sent, string(b))
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Here is the context."}}]}`))
	}))
	defer gw.Close()
	client := &ai.Client{BaseURL: gw.URL, APIKey: "vck_test", Model: "anthropic/claude-sonnet-5.5"}
	f := newFixture(t, func(d *Deps) { d.AI = client })

	fd := finding("/account", core.SeverityHigh)
	fd.Evidence = core.Evidence{Response: "Set-Cookie: sid=TOP-SECRET"}
	f.set(fd)
	f.scan(t)
	fp := decode[findingsResp](t, f.do(http.MethodGet, "/scout/api/findings", "")).Findings[0].Fingerprint

	st := decode[map[string]any](t, f.do(http.MethodGet, "/scout/api/ai", ""))
	if st["enabled"] != true || st["model"] != "anthropic/claude-sonnet-5.5" {
		t.Fatalf("status = %v", st)
	}

	w := f.do(http.MethodPost, "/scout/api/ai/explain/"+fp, "")
	ans := decode[ai.Answer](t, w)
	if w.Code != http.StatusOK || ans.Text != "Here is the context." || ans.Sent == nil {
		t.Fatalf("explain: %d %s", w.Code, w.Body)
	}
	if w := f.do(http.MethodPost, "/scout/api/ai/summary", ""); w.Code != http.StatusOK {
		t.Fatalf("summary: %d %s", w.Code, w.Body)
	}
	if w := f.do(http.MethodPost, "/scout/api/ai/explain/unknown", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown finding: %d", w.Code)
	}

	for _, body := range sent {
		if strings.Contains(body, "TOP-SECRET") || strings.Contains(body, "localhost") {
			t.Fatalf("unredacted data reached the gateway:\n%s", body)
		}
	}
}
