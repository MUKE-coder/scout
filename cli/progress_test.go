package cli

import (
	"bytes"
	"testing"
)

// The scan path calls stop() explicitly and again via defer. On a terminal the
// reporter is active (unsub != nil), so stop() must tolerate being called more
// than once without panicking on a closed channel.
func TestProgressStopIdempotent(t *testing.T) {
	var buf bytes.Buffer
	p := &progressReporter{w: &buf, stopCh: make(chan struct{}), unsub: func() {}}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		<-p.stopCh
	}()

	p.stop()
	p.stop() // must not panic ("close of closed channel")
	p.stop()
}

// An inert reporter (non-terminal writer) stops cleanly too.
func TestProgressStopInert(t *testing.T) {
	p := &progressReporter{w: &bytes.Buffer{}} // unsub nil => inert
	p.stop()
	p.stop()
}
