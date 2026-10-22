package engine

import (
	"context"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/storage"
)

func assetFinding(value string, sev core.Severity, conf core.Confidence) core.Finding {
	return core.Finding{Title: value, Severity: sev, Confidence: conf, Asset: core.Asset{Kind: core.AssetURL, Value: value}}
}

func TestDedupeKeepsWorst(t *testing.T) {
	e := newEngine(t, Options{},
		check("dup", core.ModePassive, func(context.Context, core.Target) ([]core.Finding, error) {
			return []core.Finding{
				assetFinding("/a", core.SeverityLow, core.ConfidenceConfirmed),
				assetFinding("/b", core.SeverityMedium, core.ConfidenceLikely),
				assetFinding("/a", core.SeverityHigh, core.ConfidencePossible),
			}, nil
		}),
	)
	res, _ := e.Run(context.Background(), Request{Target: localTarget})
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 after dedupe", len(res.Findings))
	}
	a := res.Findings[0]
	if a.Title != "/a" || a.Severity != core.SeverityHigh || a.Confidence != core.ConfidenceConfirmed {
		t.Fatalf("merged finding = %+v", a)
	}
}

// historyEngine returns an engine whose single check emits the given assets,
// backed by store, with a controllable clock.
func historyEngine(t *testing.T, store storage.Store, clock *time.Time, assets *[]string) *Engine {
	t.Helper()
	return newEngine(t, Options{Store: store, Now: func() time.Time { return *clock }},
		check("hist", core.ModePassive, func(context.Context, core.Target) ([]core.Finding, error) {
			var out []core.Finding
			for _, a := range *assets {
				out = append(out, assetFinding(a, core.SeverityMedium, core.ConfidenceConfirmed))
			}
			return out, nil
		}),
	)
}

func TestHistoryMergeAndPersist(t *testing.T) {
	store := storage.NewMemory(10)
	day1 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	clock := day1
	assets := []string{"/a", "/b"}
	e := historyEngine(t, store, &clock, &assets)
	ctx := context.Background()

	first, err := e.Run(ctx, Request{Target: localTarget})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range first.Findings {
		if !f.FirstSeen.Equal(day1) || !f.LastSeen.Equal(day1) || f.Status != core.StatusOpen {
			t.Fatalf("new finding stamps wrong: %+v", f)
		}
	}
	if _, err := store.GetScan(ctx, first.ID); err != nil {
		t.Fatalf("scan not persisted: %v", err)
	}

	// The user accepts the risk on /b between scans.
	saved, _ := store.GetScan(ctx, first.ID)
	for i := range saved.Findings {
		if saved.Findings[i].Title == "/b" {
			saved.Findings[i].Status = core.StatusAcceptedRisk
		}
	}
	_ = store.SaveScan(ctx, saved)

	day2 := day1.Add(24 * time.Hour)
	clock = day2
	assets = []string{"/a", "/b", "/c"}
	second, _ := e.Run(ctx, Request{Target: localTarget})

	got := map[string]core.Finding{}
	for _, f := range second.Findings {
		got[f.Title] = f
	}
	if f := got["/a"]; !f.FirstSeen.Equal(day1) || !f.LastSeen.Equal(day2) || f.Status != core.StatusOpen {
		t.Fatalf("/a should keep FirstSeen and refresh LastSeen: %+v", f)
	}
	if f := got["/b"]; f.Status != core.StatusAcceptedRisk {
		t.Fatalf("/b should keep accepted-risk: %+v", f)
	}
	if f := got["/c"]; !f.FirstSeen.Equal(day2) {
		t.Fatalf("/c is new: %+v", f)
	}
}

func TestEventsPublished(t *testing.T) {
	bus := NewBus()
	events, unsubscribe := bus.Subscribe(100)
	defer unsubscribe()
	e := newEngine(t, Options{Bus: bus},
		check("a", core.ModePassive, returns("x", "y")),
		check("b", core.ModePassive, returns("z")),
	)
	res, _ := e.Run(context.Background(), Request{Target: localTarget})

	counts := map[EventType]int{}
	var last Event
	for len(events) > 0 {
		ev := <-events
		if ev.ScanID != res.ID {
			t.Fatalf("event for wrong scan: %+v", ev)
		}
		counts[ev.Type]++
		last = ev
	}
	if counts[EventScanStarted] != 1 || counts[EventCheckFinished] != 2 || counts[EventFinding] != 3 || counts[EventScanFinished] != 1 {
		t.Fatalf("event counts = %v", counts)
	}
	if last.Type != EventScanFinished || last.Count != 3 || last.Result == nil || last.Result.Findings != nil {
		t.Fatalf("final event = %+v", last)
	}
}

func TestBusNeverBlocks(t *testing.T) {
	bus := NewBus()
	_, unsubscribe := bus.Subscribe(1) // never read
	defer unsubscribe()
	done := make(chan struct{})
	go func() {
		for range 100 {
			bus.Publish(Event{Type: EventFinding})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on a full subscriber")
	}
	if bus.Dropped() != 99 {
		t.Fatalf("dropped = %d, want 99", bus.Dropped())
	}
}

func TestUnsubscribeIdempotent(t *testing.T) {
	bus := NewBus()
	ch, unsubscribe := bus.Subscribe(1)
	unsubscribe()
	unsubscribe()
	if _, open := <-ch; open {
		t.Fatal("channel should be closed")
	}
	bus.Publish(Event{}) // must not panic on closed channel
}
