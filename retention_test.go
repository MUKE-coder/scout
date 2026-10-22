package scout

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/storage"
)

func seedScans(t *testing.T, store storage.Store, now time.Time, ages ...time.Duration) {
	t.Helper()
	for i, age := range ages {
		at := now.Add(-age)
		sc := core.ScanResult{ID: string(rune('a' + i)), Target: core.Target{Name: "t"}, StartedAt: at, FinishedAt: at}
		if err := store.SaveScan(context.Background(), sc); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrune(t *testing.T) {
	store := storage.NewMemory(10)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	seedScans(t, store, now, time.Hour, 10*24*time.Hour, 100*24*time.Hour, 200*24*time.Hour)

	n, err := Prune(context.Background(), store, 90*24*time.Hour, now)
	if err != nil || n != 2 {
		t.Fatalf("Prune = %d, %v; want 2 old scans removed", n, err)
	}
	left, _ := store.ListScans(context.Background(), 0)
	if len(left) != 2 {
		t.Fatalf("left = %d", len(left))
	}
	if n, _ := Prune(context.Background(), store, 0, now); n != 0 {
		t.Fatal("zero retention must keep everything")
	}
}

func TestPrunerStopsOnCancel(t *testing.T) {
	store := storage.NewMemory(10)
	seedScans(t, store, time.Now(), 400*24*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runPruner(ctx, store, 90*24*time.Hour, time.Millisecond, slog.New(slog.DiscardHandler))
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if left, _ := store.ListScans(context.Background(), 0); len(left) == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if left, _ := store.ListScans(context.Background(), 0); len(left) != 0 {
		t.Fatal("pruner did not run")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pruner did not stop on cancel")
	}
}
