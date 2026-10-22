package alerts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/storage"
)

func fd(path string, sev core.Severity, at time.Time) core.Finding {
	f := core.Finding{CheckID: "fixture", Title: "Issue at " + path, Severity: sev, Status: core.StatusOpen,
		Asset: core.Asset{Kind: core.AssetURL, Value: "https://shop.example" + path}, FirstSeen: at, LastSeen: at}
	f.Normalize()
	return f
}

func saveScan(t *testing.T, store storage.Store, id string, at time.Time, fs ...core.Finding) {
	t.Helper()
	sc := core.ScanResult{ID: id, Target: core.Target{Name: "shop"}, StartedAt: at, FinishedAt: at, Findings: fs, Grade: "C", Score: 72}
	if err := store.SaveScan(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
}

func TestBuildOnlyNewAndRegressedAboveThreshold(t *testing.T) {
	store := storage.NewMemory(10)
	d1 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	d2, d3 := d1.Add(24*time.Hour), d1.Add(48*time.Hour)
	saveScan(t, store, "s1", d1, fd("/old", core.SeverityHigh, d1), fd("/gone", core.SeverityHigh, d1))
	saveScan(t, store, "s2", d2, fd("/old", core.SeverityHigh, d2))
	saveScan(t, store, "s3", d3, fd("/old", core.SeverityHigh, d3), fd("/gone", core.SeverityHigh, d3),
		fd("/new-high", core.SeverityHigh, d3), fd("/new-low", core.SeverityLow, d3))

	d := &Dispatcher{Store: store, MinSeverity: core.SeverityHigh, DashboardURL: "https://scout.example/scout/ui/"}
	a, err := d.Build(context.Background(), "s3")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.New) != 1 || a.New[0].Asset.Value != "https://shop.example/new-high" {
		t.Fatalf("new = %+v", a.New)
	}
	if len(a.Regressed) != 1 || a.Regressed[0].Asset.Value != "https://shop.example/gone" {
		t.Fatalf("regressed = %+v", a.Regressed)
	}
	if !strings.Contains(a.Summary(), "1 new and 1 regressed finding(s) at or above high on shop (grade C, 72.0)") {
		t.Fatalf("summary = %q", a.Summary())
	}

	// A scan with nothing new above the threshold sends nothing.
	if _, err := d.Build(context.Background(), "s2"); err != errNothingToSend {
		t.Fatalf("s2: err = %v", err)
	}
	// Unsaved (ephemeral) scans are skipped.
	if _, err := d.Build(context.Background(), "nope"); err != storage.ErrNotFound {
		t.Fatalf("missing scan: err = %v", err)
	}
}

func sampleAlert() Alert {
	at := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	return Alert{Target: "shop", ScanID: "s1", Grade: "D", Score: 64.2, Threshold: core.SeverityHigh, At: at,
		New: []core.Finding{fd("/a", core.SeverityCritical, at)}, DashboardURL: "https://scout.example/scout/ui/"}
}

func capture(t *testing.T) (*httptest.Server, *http.Request, *[]byte) {
	t.Helper()
	var (
		req  http.Request
		body []byte
		mu   sync.Mutex
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		req = *r
		body, _ = io.ReadAll(r.Body)
	}))
	t.Cleanup(srv.Close)
	return srv, &req, &body
}

func TestSlackAndDiscord(t *testing.T) {
	srv, _, body := capture(t)
	if err := (Slack{WebhookURL: srv.URL}).Notify(context.Background(), sampleAlert()); err != nil {
		t.Fatal(err)
	}
	var slack map[string]string
	_ = json.Unmarshal(*body, &slack)
	if !strings.Contains(slack["text"], "1 new finding(s)") || !strings.Contains(slack["text"], "[critical] Issue at /a") {
		t.Fatalf("slack body = %s", *body)
	}

	long := sampleAlert()
	for i := 0; i < 200; i++ {
		long.New = append(long.New, fd("/x", core.SeverityHigh, long.At))
	}
	long.New[0].Title = strings.Repeat("x", 3000)
	if err := (Discord{WebhookURL: srv.URL}).Notify(context.Background(), long); err != nil {
		t.Fatal(err)
	}
	var discord map[string]string
	_ = json.Unmarshal(*body, &discord)
	if n := len([]rune(discord["content"])); n > 2000 {
		t.Fatalf("discord content %d chars, limit 2000", n)
	}
}

func TestWebhookSignature(t *testing.T) {
	srv, req, body := capture(t)
	if err := (Webhook{URL: srv.URL, Secret: "s3cret"}).Notify(context.Background(), sampleAlert()); err != nil {
		t.Fatal(err)
	}
	ts, sig := req.Header.Get("X-Scout-Timestamp"), req.Header.Get("X-Scout-Signature")
	if !VerifyWebhook("s3cret", ts, sig, *body, time.Now(), 5*time.Minute) {
		t.Fatal("receiver could not verify the signature")
	}
	if VerifyWebhook("wrong", ts, sig, *body, time.Now(), 5*time.Minute) {
		t.Fatal("wrong secret verified")
	}
	if VerifyWebhook("s3cret", ts, sig, append(*body, ' '), time.Now(), 5*time.Minute) {
		t.Fatal("tampered body verified")
	}
	if VerifyWebhook("s3cret", ts, sig, *body, time.Now().Add(time.Hour), 5*time.Minute) {
		t.Fatal("stale timestamp verified")
	}
	var p WebhookPayload
	if err := json.Unmarshal(*body, &p); err != nil || p.Event != "scan.alert" || p.Target != "shop" || len(p.New) != 1 {
		t.Fatalf("payload = %+v %v", p, err)
	}
}

func TestWebhookErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer srv.Close()
	if err := (Webhook{URL: srv.URL, Secret: "x"}).Notify(context.Background(), sampleAlert()); err == nil {
		t.Fatal("non-2xx should be an error")
	}
}

func TestEmail(t *testing.T) {
	var gotAddr string
	var gotMsg []byte
	old := sendMail
	sendMail = func(addr string, _ smtp.Auth, _ string, _ []string, msg []byte) error {
		gotAddr, gotMsg = addr, msg
		return nil
	}
	defer func() { sendMail = old }()

	a := sampleAlert()
	a.Target = "shop\r\nBcc: attacker@example.com" // injected via config or scanned data
	e := Email{Host: "smtp.example.com", From: "scout@example.com", To: []string{"ops@example.com"}}
	if err := e.Notify(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	msg := string(gotMsg)
	if gotAddr != "smtp.example.com:587" || !strings.Contains(msg, "Subject: Scout: 1 new finding(s)") {
		t.Fatalf("addr %s msg:\n%s", gotAddr, msg)
	}
	headers := msg[:strings.Index(msg, "\r\n\r\n")]
	if strings.Contains(headers, "\r\nBcc:") {
		t.Fatalf("header injection not neutralized:\n%s", headers)
	}
	if err := (Email{Host: "x"}).Notify(context.Background(), a); err == nil {
		t.Fatal("no recipients should fail")
	}
}

type recorder struct {
	mu     sync.Mutex
	alerts []Alert
}

func (*recorder) Name() string { return "recorder" }
func (r *recorder) Notify(_ context.Context, a Alert) error {
	r.mu.Lock()
	r.alerts = append(r.alerts, a)
	r.mu.Unlock()
	return nil
}

func TestDispatcherRunsOnScanFinished(t *testing.T) {
	store := storage.NewMemory(10)
	bus := engine.NewBus()
	rec := &recorder{}
	d := &Dispatcher{Notifiers: []Notifier{rec}, MinSeverity: core.SeverityHigh, Store: store}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx, bus); close(done) }()
	time.Sleep(20 * time.Millisecond) // let Run subscribe

	at := time.Now()
	saveScan(t, store, "s1", at, fd("/a", core.SeverityCritical, at))
	bus.Publish(engine.Event{Type: engine.EventScanFinished, ScanID: "s1"})
	bus.Publish(engine.Event{Type: engine.EventScanFinished, ScanID: "ephemeral"}) // not stored: ignored

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		n := len(rec.alerts)
		rec.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if len(rec.alerts) != 1 || rec.alerts[0].ScanID != "s1" {
		t.Fatalf("alerts = %+v", rec.alerts)
	}
}
