package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/gin-gonic/gin"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/storage"
)

type fixture struct {
	r     *gin.Engine
	token string
	store storage.Store
	kill  *engine.KillSwitch
	wg    *sync.WaitGroup

	mu       sync.Mutex
	findings []core.Finding // what the fixture check reports next
}

var site = core.Target{Name: "site", URL: "http://localhost:1", Environment: core.EnvDev}

func finding(path string, sev core.Severity) core.Finding {
	return core.Finding{Title: "Issue at " + path, Category: core.CategoryApp, Severity: sev, Confidence: core.ConfidenceConfirmed,
		Asset: core.Asset{Kind: core.AssetURL, Value: "http://localhost:1" + path, Path: path, Exposure: core.ExposureInternal}}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	f := &fixture{store: storage.NewMemory(50), kill: engine.NewKillSwitch(), wg: &sync.WaitGroup{}}
	reg := core.NewRegistry()
	reg.MustRegister(core.CheckFunc{CheckID: "fixture.check", CheckCategory: core.CategoryApp, CheckMode: core.ModePassive,
		Fn: func(context.Context, core.Target) ([]core.Finding, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return append([]core.Finding(nil), f.findings...), nil
		}})
	bus := engine.NewBus()
	eng := engine.New(reg, engine.Options{Store: f.store, Bus: bus, Kill: f.kill})
	auth := NewAuth([]byte("secret-0123456789abcdef0123456789"), "ops", "pw")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); f.wg.Wait() })
	spawn := func(fn func(context.Context)) {
		f.wg.Add(1)
		go func() { defer f.wg.Done(); fn(ctx) }()
	}
	f.r = gin.New()
	New(Deps{Auth: auth, Store: f.store, Engine: eng, Bus: bus, Kill: f.kill, Go: spawn,
		Settings: Settings{AppName: "Test", Environment: core.EnvDev, Mode: core.ModeSafe, Targets: []core.Target{site}}}).
		Register(f.r.Group("/scout"))

	w := f.do(http.MethodPost, "/scout/api/auth/login", `{"username":"ops","password":"pw"}`)
	var resp loginResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	f.token = resp.Token
	return f
}

func (f *fixture) set(fs ...core.Finding) {
	f.mu.Lock()
	f.findings = fs
	f.mu.Unlock()
}

func (f *fixture) do(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, req)
	return w
}

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("bad JSON (%d): %v\n%s", w.Code, err, w.Body)
	}
	return v
}

// scan starts a dashboard scan and waits for it to be stored.
func (f *fixture) scan(t *testing.T) string {
	t.Helper()
	w := f.do(http.MethodPost, "/scout/api/scans", `{"target":"site"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("start scan: %d %s", w.Code, w.Body)
	}
	id := decode[map[string]string](t, w)["id"]
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := f.store.GetScan(context.Background(), id); err == nil {
			return id
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scan %s never finished", id)
	return ""
}

type findingsResp struct {
	Findings []findingRow `json:"findings"`
}

func TestScanFindingsAndChanges(t *testing.T) {
	f := newFixture(t)
	f.set(finding("/a", core.SeverityHigh), finding("/b", core.SeverityLow))
	f.scan(t)

	rows := decode[findingsResp](t, f.do(http.MethodGet, "/scout/api/findings", "")).Findings
	if len(rows) != 2 || rows[0].Severity != core.SeverityHigh || rows[0].Change != "new" || rows[0].Target != "site" {
		t.Fatalf("first scan rows = %+v", rows)
	}

	// Second scan: /a stays, /b gone, /c appears.
	f.set(finding("/a", core.SeverityHigh), finding("/c", core.SeverityMedium))
	f.scan(t)
	rows = decode[findingsResp](t, f.do(http.MethodGet, "/scout/api/findings", "")).Findings
	changes := map[string]string{}
	for _, r := range rows {
		changes[r.Asset.Path] = r.Change
	}
	if changes["/a"] != "unchanged" || changes["/c"] != "new" || len(rows) != 2 {
		t.Fatalf("changes = %v", changes)
	}

	// Third scan: /b returns, so it is regressed rather than new.
	f.set(finding("/a", core.SeverityHigh), finding("/b", core.SeverityLow), finding("/c", core.SeverityMedium))
	f.scan(t)
	rows = decode[findingsResp](t, f.do(http.MethodGet, "/scout/api/findings?change=regressed", "")).Findings
	if len(rows) != 1 || rows[0].Asset.Path != "/b" {
		t.Fatalf("regressed = %+v", rows)
	}

	// Filters.
	if rows := decode[findingsResp](t, f.do(http.MethodGet, "/scout/api/findings?severity=high", "")).Findings; len(rows) != 1 {
		t.Fatalf("severity filter = %d rows", len(rows))
	}
	if rows := decode[findingsResp](t, f.do(http.MethodGet, "/scout/api/findings?q=issue+at+/c", "")).Findings; len(rows) != 1 {
		t.Fatalf("search = %d rows", len(rows))
	}
}

func TestDiffEndpoint(t *testing.T) {
	f := newFixture(t)
	f.set(finding("/a", core.SeverityHigh), finding("/b", core.SeverityLow))
	first := f.scan(t)
	f.set(finding("/a", core.SeverityHigh), finding("/c", core.SeverityMedium))
	second := f.scan(t)

	// Arguments in either order are compared older -> newer.
	w := f.do(http.MethodGet, "/scout/api/diff?from="+second+"&to="+first, "")
	got := decode[struct {
		Diff struct {
			New, Fixed, Unchanged, Regressed []core.Finding
		} `json:"diff"`
		SameTarget bool `json:"same_target"`
	}](t, w)
	if len(got.Diff.New) != 1 || len(got.Diff.Fixed) != 1 || len(got.Diff.Unchanged) != 1 || !got.SameTarget {
		t.Fatalf("diff = %s", w.Body)
	}
	if w := f.do(http.MethodGet, "/scout/api/diff?from=nope&to="+first, ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown scan: %d", w.Code)
	}
}

func TestSurfaceEndpoint(t *testing.T) {
	f := newFixture(t)
	f.set(finding("/admin", core.SeverityHigh))
	f.scan(t)
	w := f.do(http.MethodGet, "/scout/api/surface", "")
	got := decode[struct {
		Nodes []struct {
			Label string `json:"label"`
			Open  int    `json:"open"`
		} `json:"nodes"`
	}](t, w)
	if len(got.Nodes) != 1 || got.Nodes[0].Label != "localhost" || got.Nodes[0].Open != 1 {
		t.Fatalf("surface = %s", w.Body)
	}
}

func TestOverview(t *testing.T) {
	f := newFixture(t)
	f.set(finding("/a", core.SeverityCritical))
	f.scan(t)
	w := f.do(http.MethodGet, "/scout/api/overview", "")
	ov := decode[struct {
		Targets []targetOverview `json:"targets"`
		Killed  bool             `json:"killed"`
	}](t, w)
	if len(ov.Targets) != 1 {
		t.Fatalf("overview = %s", w.Body)
	}
	tg := ov.Targets[0]
	if tg.Report.Grade != "F" || tg.Open["critical"] != 1 || len(tg.FixNext) != 1 || len(tg.Trend) != 1 {
		t.Fatalf("target overview = %+v", tg)
	}
}

func TestStatusAndVerify(t *testing.T) {
	f := newFixture(t)
	f.set(finding("/a", core.SeverityHigh), finding("/b", core.SeverityLow))
	f.scan(t)
	rows := decode[findingsResp](t, f.do(http.MethodGet, "/scout/api/findings", "")).Findings
	fpA, fpB := rows[0].Fingerprint, rows[1].Fingerprint

	// Accepting a risk needs a reason; an expiry must be in the future.
	if w := f.do(http.MethodPost, "/scout/api/findings/status", `{"fingerprints":["`+fpB+`"],"status":"accepted-risk"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("accept without reason: %d", w.Code)
	}
	if w := f.do(http.MethodPost, "/scout/api/findings/status", `{"fingerprints":["`+fpB+`"],"status":"accepted-risk","reason":"x","until":"2001-01-01"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("past expiry: %d", w.Code)
	}
	until := time.Now().Add(30 * 24 * time.Hour).Format("2006-01-02")
	w := f.do(http.MethodPost, "/scout/api/findings/status",
		`{"fingerprints":["`+fpB+`"],"status":"accepted-risk","reason":"Behind the VPN","until":"`+until+`"}`)
	if w.Code != http.StatusOK || decode[map[string]int](t, w)["updated"] != 1 {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	accepted := decode[struct {
		Finding findingRow `json:"finding"`
	}](t, f.do(http.MethodGet, "/scout/api/findings/"+fpB, "")).Finding
	if accepted.StatusReason != "Behind the VPN" || accepted.StatusBy != "ops" || accepted.StatusUntil == nil {
		t.Fatalf("decision not recorded: %+v", accepted)
	}
	// Reopening clears the decision.
	f.do(http.MethodPost, "/scout/api/findings/status", `{"fingerprints":["`+fpB+`"],"status":"open"}`)
	reopened := decode[struct {
		Finding findingRow `json:"finding"`
	}](t, f.do(http.MethodGet, "/scout/api/findings/"+fpB, "")).Finding
	if reopened.StatusReason != "" || reopened.StatusUntil != nil {
		t.Fatalf("reopen should clear the decision: %+v", reopened)
	}
	f.do(http.MethodPost, "/scout/api/findings/status", `{"fingerprints":["`+fpB+`"],"status":"accepted-risk","reason":"Behind the VPN"}`)
	if rows := decode[findingsResp](t, f.do(http.MethodGet, "/scout/api/findings?status=accepted-risk", "")).Findings; len(rows) != 1 {
		t.Fatalf("accepted rows = %d", len(rows))
	}
	if w := f.do(http.MethodPost, "/scout/api/findings/status", `{"fingerprints":["x"],"status":"ignored"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad status accepted: %d", w.Code)
	}

	// Verify while still present: not fixed.
	if v := decode[map[string]any](t, f.do(http.MethodPost, "/scout/api/findings/"+fpA+"/verify", "")); v["fixed"] != false {
		t.Fatalf("verify present = %v", v)
	}
	// The issue is fixed: verify marks it so, without adding a scan.
	before, _ := f.store.ListScans(context.Background(), 0)
	f.set(finding("/b", core.SeverityLow))
	if v := decode[map[string]any](t, f.do(http.MethodPost, "/scout/api/findings/"+fpA+"/verify", "")); v["fixed"] != true {
		t.Fatalf("verify fixed = %v", v)
	}
	after, _ := f.store.ListScans(context.Background(), 0)
	if len(after) != len(before) {
		t.Fatal("verify must not store a new scan")
	}
	detail := decode[struct {
		Finding findingRow     `json:"finding"`
		History []historyEntry `json:"history"`
	}](t, f.do(http.MethodGet, "/scout/api/findings/"+fpA, ""))
	if detail.Finding.Status != core.StatusFixed || len(detail.History) != 1 {
		t.Fatalf("detail = %+v", detail)
	}
}

func TestKillSwitchAndTargets(t *testing.T) {
	f := newFixture(t)
	if w := f.do(http.MethodPost, "/scout/api/scans", `{"target":"https://not-configured.example"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unconfigured target must be refused: %d", w.Code)
	}
	f.do(http.MethodPost, "/scout/api/kill", "")
	if w := f.do(http.MethodPost, "/scout/api/scans", `{"target":"site"}`); w.Code != http.StatusConflict {
		t.Fatalf("scan while killed: %d", w.Code)
	}
	if st := decode[map[string]any](t, f.do(http.MethodGet, "/scout/api/status", "")); st["killed"] != true {
		t.Fatalf("status = %v", st)
	}
	f.do(http.MethodPost, "/scout/api/resume", "")
	f.scan(t)
}

func TestExportCSV(t *testing.T) {
	f := newFixture(t)
	evil := finding("/x", core.SeverityLow)
	evil.Title = "=HYPERLINK(\"http://evil\")"
	f.set(evil)
	f.scan(t)
	w := f.do(http.MethodGet, "/scout/api/export?format=csv", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Disposition"), ".csv") {
		t.Fatalf("export: %d %v", w.Code, w.Header())
	}
	if strings.Contains(w.Body.String(), ",=HYPERLINK") || !strings.Contains(w.Body.String(), "'=HYPERLINK") {
		t.Fatalf("formula not neutralized:\n%s", w.Body)
	}
	if w := f.do(http.MethodGet, "/scout/api/export?format=json", ""); !strings.Contains(w.Body.String(), `"tool": "scout"`) {
		t.Fatal("json export broken")
	}
}

func TestEndpointsRequireAuth(t *testing.T) {
	f := newFixture(t)
	f.token = ""
	for _, p := range []string{"/scout/api/overview", "/scout/api/findings", "/scout/api/settings", "/scout/api/export", "/scout/ws/live"} {
		if w := f.do(http.MethodGet, p, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without token: %d", p, w.Code)
		}
	}
}

func TestLiveWebSocket(t *testing.T) {
	f := newFixture(t)
	f.set(finding("/a", core.SeverityHigh))
	srv := httptest.NewServer(f.r)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/scout/ws/live?token="+f.token, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	f.scan(t)
	seen := map[engine.EventType]bool{}
	for !seen[engine.EventScanFinished] {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v (seen %v)", err, seen)
		}
		var ev engine.Event
		if err := json.Unmarshal(msg, &ev); err != nil {
			t.Fatal(err)
		}
		seen[ev.Type] = true
	}
	if !seen[engine.EventScanStarted] || !seen[engine.EventCheckFinished] || !seen[engine.EventFinding] {
		t.Fatalf("events = %v", seen)
	}
	running := decode[map[string][]scanProgress](t, f.do(http.MethodGet, "/scout/api/scans/running", ""))["scans"]
	if len(running) != 1 || !running[0].Finished || running[0].Findings != 1 {
		t.Fatalf("tracker = %+v", running)
	}
}
