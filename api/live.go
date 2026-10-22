package api

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/gin-gonic/gin"

	"github.com/MUKE-coder/scout/engine"
)

// scanProgress is the live state of one scan, rebuilt from bus events so a
// dashboard opened mid-scan sees where things stand.
type scanProgress struct {
	ID       string          `json:"id"`
	Started  time.Time       `json:"started"`
	Total    int             `json:"total"`
	Done     int             `json:"done"`
	Findings int             `json:"findings"`
	Checks   []checkProgress `json:"checks"`
	Finished bool            `json:"finished"`
	Error    string          `json:"error,omitempty"`
}

type checkProgress struct {
	ID       string `json:"id"`
	Findings int    `json:"findings"`
	Error    string `json:"error,omitempty"`
}

// tracker keeps recent scan progress (running and the last few finished).
type tracker struct {
	mu    sync.Mutex
	scans map[string]*scanProgress
}

const keepFinished = 10

func newTracker(bus *engine.Bus, spawn func(func(context.Context))) *tracker {
	t := &tracker{scans: map[string]*scanProgress{}}
	events, unsubscribe := bus.Subscribe(256)
	spawn(func(ctx context.Context) {
		defer unsubscribe()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-events:
				if !ok {
					return
				}
				t.apply(ev)
			}
		}
	})
	return t
}

func (t *tracker) apply(ev engine.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.scans[ev.ScanID]
	if p == nil {
		if ev.Type != engine.EventScanStarted {
			return
		}
		p = &scanProgress{ID: ev.ScanID, Started: ev.Time}
		t.scans[ev.ScanID] = p
	}
	switch ev.Type {
	case engine.EventScanStarted:
		p.Total = ev.Total
	case engine.EventCheckFinished:
		p.Done = ev.Done
		p.Findings += ev.Count
		p.Checks = append(p.Checks, checkProgress{ID: ev.CheckID, Findings: ev.Count, Error: ev.Error})
	case engine.EventScanFinished:
		p.Finished = true
		p.Done = p.Total
		t.trim()
	}
}

func (t *tracker) failed(id string, err error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scans[id] = &scanProgress{ID: id, Started: time.Now(), Finished: true, Error: err.Error()}
	t.trim()
}

// trim drops the oldest finished scans beyond keepFinished. Caller holds t.mu.
func (t *tracker) trim() {
	var finished []*scanProgress
	for _, p := range t.scans {
		if p.Finished {
			finished = append(finished, p)
		}
	}
	if len(finished) <= keepFinished {
		return
	}
	sort.Slice(finished, func(i, j int) bool { return finished[i].Started.Before(finished[j].Started) })
	for _, p := range finished[:len(finished)-keepFinished] {
		delete(t.scans, p.ID)
	}
}

func (t *tracker) snapshot() []scanProgress {
	if t == nil {
		return []scanProgress{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]scanProgress, 0, len(t.scans))
	for _, p := range t.scans {
		cp := *p
		cp.Checks = append([]checkProgress(nil), p.Checks...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out
}

// live streams bus events to a WebSocket client as JSON messages. A slow
// client misses events (the bus never blocks scans) and can resync from
// GET /scans/running.
func (s *Server) live(c *gin.Context) {
	// Subscribe before completing the handshake, so no event published
	// after the client is connected can be missed.
	events, unsubscribe := s.d.Bus.Subscribe(256)
	defer unsubscribe()

	conn, err := websocket.Accept(c.Writer, c.Request, &websocket.AcceptOptions{})
	if err != nil {
		return // Accept already wrote the HTTP error
	}
	defer conn.CloseNow()
	ctx := conn.CloseRead(c.Request.Context()) // we only write; this notices client close

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = conn.Close(websocket.StatusNormalClosure, "") // the client already went away
			return
		case <-ping.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		case ev, ok := <-events:
			if !ok {
				return
			}
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = conn.Write(wctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
