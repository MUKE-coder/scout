package scout

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrShutdownTimeout is returned when goroutines outlive the shutdown deadline.
var ErrShutdownTimeout = errors.New("scout: shutdown timed out waiting for goroutines")

// Lifecycle owns Scout's background goroutines. Every goroutine is started
// through Go and receives a context that is cancelled on Shutdown, which then
// waits for all of them to return.
type Lifecycle struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// NewLifecycle returns a lifecycle derived from parent.
func NewLifecycle(parent context.Context) *Lifecycle {
	// cancel is kept on the struct and called by Shutdown.
	ctx, cancel := context.WithCancel(parent) // #nosec G118 -- cancelled in Shutdown
	return &Lifecycle{ctx: ctx, cancel: cancel}
}

// Context is cancelled when shutdown begins.
func (l *Lifecycle) Context() context.Context { return l.ctx }

// Go runs fn in a tracked goroutine.
func (l *Lifecycle) Go(fn func(ctx context.Context)) {
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		fn(l.ctx)
	}()
}

// Shutdown cancels the context and waits up to timeout for goroutines to
// return. It is safe to call more than once.
func (l *Lifecycle) Shutdown(timeout time.Duration) error {
	l.once.Do(l.cancel)
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return ErrShutdownTimeout
	}
}
