package integrations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/storage"
)

func TestCombinedScore(t *testing.T) {
	cases := []struct {
		exposure, runtime, want float64
	}{
		{90, 0, 90}, // runtime unknown -> exposure unchanged
		{100, 100, 100},
		{64, 100, 80}, // sqrt(64*100) = 80
		{50, 50, 50},
		{150, -5, 100}, // clamped
	}
	for _, c := range cases {
		if got := CombinedScore(c.exposure, c.runtime); got != c.want {
			t.Errorf("CombinedScore(%v,%v) = %v, want %v", c.exposure, c.runtime, got, c.want)
		}
	}
}

// sibling is a fake Pulse/Sentinel: a health endpoint and a capture endpoint.
func sibling(t *testing.T, healthStatus int) (*httptest.Server, *[]string) {
	t.Helper()
	var bodies []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/health") {
			w.WriteHeader(healthStatus)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv, &bodies
}

func sampleScan() core.ScanResult {
	at := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	return core.ScanResult{
		ID: "scan1", Target: core.Target{Name: "shop", URL: "https://shop.example.com", Environment: core.EnvProd},
		Mode: core.ModeSafe, Grade: "C", Score: 72.5, StartedAt: at, FinishedAt: at.Add(time.Minute),
		Findings: []core.Finding{{Title: "x"}},
	}
}

func TestPulseRegisterAndDetect(t *testing.T) {
	srv, bodies := sibling(t, http.StatusOK)
	p := NewPulse(srv.URL, "", "tok")
	if !p.Detect(context.Background()) || !p.Available() {
		t.Fatal("pulse should be detected")
	}
	if err := p.RegisterScan(context.Background(), RefOf(sampleScan())); err != nil {
		t.Fatal(err)
	}
	var run pulseTestRun
	_ = json.Unmarshal([]byte((*bodies)[0]), &run)
	if run.Source != "scout" || run.Kind != "security-scan" || run.ScanID != "scan1" || run.Grade != "C" {
		t.Fatalf("test-run payload = %+v", run)
	}
}

func TestSentinelPushAndDetect(t *testing.T) {
	srv, bodies := sibling(t, http.StatusUnauthorized) // present but needs auth: still "detected"
	s := NewSentinel(srv.URL, "", "")
	if !s.Detect(context.Background()) {
		t.Fatal("a sibling that answers (even 401) is present")
	}
	if err := s.PushScore(context.Background(), RefOf(sampleScan())); err != nil {
		t.Fatal(err)
	}
	var score sentinelScore
	_ = json.Unmarshal([]byte((*bodies)[0]), &score)
	if score.Source != "scout" || score.Exposure != 72.5 || score.Target != "shop" {
		t.Fatalf("score payload = %+v", score)
	}
}

func TestDetectAbsentSibling(t *testing.T) {
	if NewPulse("", "", "").Detect(context.Background()) {
		t.Fatal("no URL means not detected")
	}
	if NewPulse("http://127.0.0.1:0", "", "").Detect(context.Background()) {
		t.Fatal("unreachable host means not detected")
	}
}

func TestDispatcherForwardsFinishedScans(t *testing.T) {
	srv, bodies := sibling(t, http.StatusOK)
	store := storage.NewMemory(10)
	_ = store.SaveScan(context.Background(), sampleScan())
	bus := engine.NewBus()
	d := &Dispatcher{Pulse: NewPulse(srv.URL, "", ""), Sentinel: NewSentinel(srv.URL, "", ""), Store: store}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx, bus); close(done) }()
	time.Sleep(30 * time.Millisecond) // let Run detect and subscribe

	bus.Publish(engine.Event{Type: engine.EventScanFinished, ScanID: "scan1"})
	bus.Publish(engine.Event{Type: engine.EventScanFinished, ScanID: "ephemeral"}) // not stored: skipped

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n := len(*bodies); n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if len(*bodies) != 2 { // one Pulse + one Sentinel, for the stored scan only
		t.Fatalf("forwarded %d payloads, want 2", len(*bodies))
	}
}

func TestDispatcherIdleWithoutSiblings(t *testing.T) {
	d := &Dispatcher{Pulse: NewPulse("http://127.0.0.1:0", "", ""), Store: storage.NewMemory(1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { d.Run(ctx, engine.NewBus()); close(done) }()
	select {
	case <-done: // returns promptly when nothing is detected
	case <-time.After(2 * time.Second):
		t.Fatal("dispatcher should return when no siblings are detected")
	}
}
