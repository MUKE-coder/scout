package engine

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/MUKE-coder/scout/core"
)

// EventType names a scan lifecycle event.
type EventType string

const (
	EventScanStarted   EventType = "scan.started"
	EventCheckFinished EventType = "check.finished"
	EventFinding       EventType = "finding"
	EventScanFinished  EventType = "scan.finished"
)

// Event is published on the Bus as a scan progresses.
type Event struct {
	Type    EventType     `json:"type"`
	ScanID  string        `json:"scan_id"`
	Time    time.Time     `json:"time"`
	CheckID string        `json:"check_id,omitempty"`
	Count   int           `json:"count,omitempty"` // findings from one check
	Error   string        `json:"error,omitempty"`
	Finding *core.Finding `json:"finding,omitempty"`
	// Total and Done report progress on scan.started and check.finished.
	Total int `json:"total,omitempty"`
	Done  int `json:"done,omitempty"`
	// Result is set on scan.finished. Findings are omitted to keep events small.
	Result *core.ScanResult `json:"result,omitempty"`
}

// Bus fans events out to subscribers. Publishing never blocks: a slow
// subscriber drops events instead of stalling the scan.
type Bus struct {
	mu      sync.RWMutex
	next    int
	subs    map[int]chan Event
	dropped atomic.Int64
}

// NewBus returns an empty bus.
func NewBus() *Bus { return &Bus{subs: make(map[int]chan Event)} }

// Subscribe returns a channel of events and a function that unsubscribes
// and closes it.
func (b *Bus) Subscribe(buffer int) (<-chan Event, func()) {
	if buffer <= 0 {
		buffer = 64
	}
	ch := make(chan Event, buffer)
	b.mu.Lock()
	id := b.next
	b.next++
	b.subs[id] = ch
	b.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, id)
			b.mu.Unlock()
			close(ch)
		})
	}
}

// Publish delivers e to every subscriber that has room.
func (b *Bus) Publish(e Event) {
	if b == nil {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default:
			b.dropped.Add(1)
		}
	}
}

// Dropped is how many events were dropped because a subscriber was full.
func (b *Bus) Dropped() int64 { return b.dropped.Load() }
