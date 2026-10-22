package scout

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLifecycleShutdownStopsGoroutines(t *testing.T) {
	l := NewLifecycle(context.Background())
	var stopped atomic.Int32
	for i := 0; i < 5; i++ {
		l.Go(func(ctx context.Context) {
			<-ctx.Done()
			stopped.Add(1)
		})
	}
	if err := l.Shutdown(time.Second); err != nil {
		t.Fatal(err)
	}
	if stopped.Load() != 5 {
		t.Fatalf("stopped = %d, want 5", stopped.Load())
	}
	if err := l.Shutdown(time.Second); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

func TestLifecycleShutdownTimeout(t *testing.T) {
	l := NewLifecycle(context.Background())
	release := make(chan struct{})
	l.Go(func(context.Context) { <-release })
	if err := l.Shutdown(20 * time.Millisecond); err != ErrShutdownTimeout {
		t.Fatalf("err = %v, want timeout", err)
	}
	close(release)
}

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	log, err := NewLogger(&buf, "warn", "json")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hidden")
	log.Warn("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), `"msg":"shown"`) {
		t.Fatalf("unexpected log output: %s", buf.String())
	}
	if _, err := NewLogger(&buf, "loud", "text"); err == nil {
		t.Fatal("expected invalid level error")
	}
	if _, err := NewLogger(&buf, "info", "xml"); err == nil {
		t.Fatal("expected invalid format error")
	}
}
