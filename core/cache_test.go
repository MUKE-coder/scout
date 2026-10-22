package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMemoComputesOncePerScan(t *testing.T) {
	ctx := WithScanCache(context.Background())
	var calls atomic.Int32
	fn := func() (int, error) { calls.Add(1); return 42, nil }

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, _ := Memo(ctx, "k", fn); v != 42 {
				t.Errorf("v = %d", v)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("fn ran %d times, want 1", calls.Load())
	}

	// A new scan gets a new cache.
	_, _ = Memo(WithScanCache(context.Background()), "k", fn)
	// No cache means no memoization.
	_, _ = Memo(context.Background(), "k", fn)
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
}
