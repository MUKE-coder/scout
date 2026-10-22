package integrations

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/storage"
)

// Dispatcher registers finished scans with any detected siblings.
type Dispatcher struct {
	Pulse    *Pulse
	Sentinel *Sentinel
	Store    storage.Store
	Logger   *slog.Logger
	Timeout  time.Duration
}

func (d *Dispatcher) log() *slog.Logger {
	if d.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return d.Logger
}

// Active reports whether any sibling is configured.
func (d *Dispatcher) Active() bool {
	return d != nil && (d.Pulse != nil || d.Sentinel != nil)
}

// Run detects siblings once, then forwards each finished, stored scan to the
// ones that are present, until ctx ends.
func (d *Dispatcher) Run(ctx context.Context, bus *engine.Bus) {
	if !d.Active() {
		return
	}
	if d.Pulse != nil && d.Pulse.Detect(ctx) {
		d.log().Info("pulse integration active", "url", d.Pulse.BaseURL)
	}
	if d.Sentinel != nil && d.Sentinel.Detect(ctx) {
		d.log().Info("sentinel integration active", "url", d.Sentinel.BaseURL)
	}
	if !d.Pulse.Available() && !d.Sentinel.Available() {
		d.log().Info("no scout siblings detected; integrations idle")
		return
	}
	events, unsubscribe := bus.Subscribe(64)
	defer unsubscribe()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if ev.Type == engine.EventScanFinished {
				d.forward(ctx, ev.ScanID)
			}
		}
	}
}

func (d *Dispatcher) forward(ctx context.Context, scanID string) {
	sc, err := d.Store.GetScan(ctx, scanID)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) { // ephemeral scans are not stored
			d.log().Error("integrations: load scan", "scan", scanID, "err", err)
		}
		return
	}
	ref := RefOf(sc)
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if d.Pulse.Available() {
		c, cancel := context.WithTimeout(ctx, timeout)
		if err := d.Pulse.RegisterScan(c, ref); err != nil {
			d.log().Error("pulse: register scan", "scan", scanID, "err", err)
		}
		cancel()
	}
	if d.Sentinel.Available() {
		c, cancel := context.WithTimeout(ctx, timeout)
		if err := d.Sentinel.PushScore(c, ref); err != nil {
			d.log().Error("sentinel: push score", "scan", scanID, "err", err)
		}
		cancel()
	}
}
