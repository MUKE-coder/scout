// Package alerts notifies Slack, Discord, email and webhooks when a scan
// finds new or regressed findings at or above a severity threshold.
package alerts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/report"
	"github.com/MUKE-coder/scout/storage"
)

// Alert is one notification: what changed in one scan.
type Alert struct {
	Target       string         `json:"target"`
	ScanID       string         `json:"scan_id"`
	Grade        string         `json:"grade"`
	Score        float64        `json:"score"`
	Threshold    core.Severity  `json:"threshold"`
	New          []core.Finding `json:"new"`
	Regressed    []core.Finding `json:"regressed"`
	DashboardURL string         `json:"dashboard_url,omitempty"`
	At           time.Time      `json:"at"`
}

// Summary is the one-line headline used by every channel.
func (a Alert) Summary() string {
	var parts []string
	if n := len(a.New); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new", n))
	}
	if n := len(a.Regressed); n > 0 {
		parts = append(parts, fmt.Sprintf("%d regressed", n))
	}
	grade := "ungraded"
	if a.Grade != "" {
		grade = fmt.Sprintf("grade %s, %.1f", a.Grade, a.Score)
	}
	return fmt.Sprintf("Scout: %s finding(s) at or above %s on %s (%s)", strings.Join(parts, " and "), a.Threshold, a.Target, grade)
}

// maxListed caps how many findings a text message lists.
const maxListed = 10

// Text renders the alert as plain text for chat and email.
func (a Alert) Text() string {
	var b strings.Builder
	b.WriteString(a.Summary())
	b.WriteString("\n")
	list := func(label string, fs []core.Finding) {
		for i, f := range fs {
			if i == maxListed {
				fmt.Fprintf(&b, "  … and %d more\n", len(fs)-maxListed)
				return
			}
			fmt.Fprintf(&b, "• %s [%s] %s — %s\n", label, f.Severity, f.Title, f.Asset.Value)
		}
	}
	list("new", a.New)
	list("regressed", a.Regressed)
	if a.DashboardURL != "" {
		fmt.Fprintf(&b, "\n%s\n", a.DashboardURL)
	}
	return b.String()
}

// Notifier delivers an alert to one channel.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, a Alert) error
}

// Dispatcher turns finished scans into alerts.
type Dispatcher struct {
	Notifiers    []Notifier
	MinSeverity  core.Severity
	DashboardURL string
	Store        storage.Store
	Logger       *slog.Logger
	// Timeout bounds each notifier call.
	Timeout time.Duration
}

// Run listens for scan.finished events until ctx ends.
func (d *Dispatcher) Run(ctx context.Context, bus *engine.Bus) {
	if len(d.Notifiers) == 0 {
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
			if ev.Type != engine.EventScanFinished {
				continue
			}
			a, err := d.Build(ctx, ev.ScanID)
			if err != nil {
				if !errors.Is(err, errNothingToSend) && !errors.Is(err, storage.ErrNotFound) {
					d.log().Error("building alert", "scan", ev.ScanID, "err", err)
				}
				continue
			}
			d.Send(ctx, a)
		}
	}
}

var errNothingToSend = errors.New("nothing new at or above the threshold")

// Build compares a stored scan with its target's previous scan and returns
// the alert, or errNothingToSend. Unsaved (ephemeral) scans return
// storage.ErrNotFound.
func (d *Dispatcher) Build(ctx context.Context, scanID string) (Alert, error) {
	sc, err := d.Store.GetScan(ctx, scanID)
	if err != nil {
		return Alert{}, err
	}
	prev := core.ScanResult{}
	seenBefore := func(string) bool { return false }
	all, err := d.Store.ListScans(ctx, 0)
	if err != nil {
		return Alert{}, err
	}
	for _, other := range all { // newest first
		if other.Target.Name == sc.Target.Name && other.StartedAt.Before(sc.StartedAt) {
			if prev, err = d.Store.GetScan(ctx, other.ID); err != nil {
				return Alert{}, err
			}
			cutoff := prev.StartedAt
			seenBefore = func(fp string) bool {
				fs, err := d.Store.ListFindings(ctx, storage.FindingFilter{Fingerprint: fp})
				if err != nil {
					return false
				}
				for _, f := range fs {
					if !f.LastSeen.IsZero() && f.LastSeen.Before(cutoff) {
						return true
					}
				}
				return false
			}
			break
		}
	}
	diff := report.DiffScans(prev, sc, seenBefore)
	a := Alert{
		Target: sc.Target.Name, ScanID: sc.ID, Grade: sc.Grade, Score: sc.Score,
		Threshold: d.MinSeverity, DashboardURL: d.DashboardURL, At: sc.FinishedAt,
		New: atLeast(diff.New, d.MinSeverity), Regressed: atLeast(diff.Regressed, d.MinSeverity),
	}
	if len(a.New)+len(a.Regressed) == 0 {
		return a, errNothingToSend
	}
	return a, nil
}

// Send delivers an alert to every notifier, logging failures.
func (d *Dispatcher) Send(ctx context.Context, a Alert) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	for _, n := range d.Notifiers {
		nctx, cancel := context.WithTimeout(ctx, timeout)
		err := n.Notify(nctx, a)
		cancel()
		if err != nil {
			d.log().Error("alert delivery failed", "channel", n.Name(), "scan", a.ScanID, "err", err)
			continue
		}
		d.log().Info("alert sent", "channel", n.Name(), "scan", a.ScanID, "new", len(a.New), "regressed", len(a.Regressed))
	}
}

func (d *Dispatcher) log() *slog.Logger {
	if d.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return d.Logger
}

func atLeast(fs []core.Finding, min core.Severity) []core.Finding {
	var out []core.Finding
	for _, f := range fs {
		if f.Severity >= min {
			out = append(out, f)
		}
	}
	return out
}
