package engine

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/MUKE-coder/scout/core"
)

// Guard errors. These are returned by the guard transport before any request
// reaches the network, so callers can tell a blocked request apart from a real
// transport failure.
var (
	// ErrKilled is returned when the global kill switch is engaged.
	ErrKilled = errors.New("scout: scan killed by kill switch")
	// ErrOutsideWindow is returned when the request falls outside the allowed
	// scan window.
	ErrOutsideWindow = errors.New("scout: request outside allowed scan window")
	// ErrOutOfScope is returned when the request target is not in scope.
	ErrOutOfScope = errors.New("scout: request target out of scope")
)

// KillSwitch is a goroutine-safe global stop control for a scan. Once Kill is
// called every in-flight and subsequent guarded request fails fast with
// ErrKilled until Resume is called. The zero value is not usable — construct
// with NewKillSwitch.
type KillSwitch struct {
	mu     sync.RWMutex
	killed bool
}

// NewKillSwitch returns a KillSwitch in the running (not killed) state.
func NewKillSwitch() *KillSwitch { return &KillSwitch{} }

// Kill engages the switch. Safe to call repeatedly and from any goroutine.
func (k *KillSwitch) Kill() {
	k.mu.Lock()
	k.killed = true
	k.mu.Unlock()
}

// Resume disengages the switch, allowing guarded requests through again.
func (k *KillSwitch) Resume() {
	k.mu.Lock()
	k.killed = false
	k.mu.Unlock()
}

// Killed reports whether the switch is currently engaged.
func (k *KillSwitch) Killed() bool {
	if k == nil {
		return false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.killed
}

// Window describes when scanning is permitted. A nil *Window allows all times.
//
// Start and End are "HH:MM" in 24-hour time, interpreted in Location. If End is
// less than or equal to Start the window wraps past midnight (e.g. 22:00–06:00).
// Days, if non-empty, restricts the window to those weekdays; an empty Days
// means every day. If Location is nil, time.Local is used.
//
// A Window is a safety control, so it fails closed: a malformed Start/End
// string causes Allows to return false.
type Window struct {
	Start, End string
	Days       []time.Weekday
	Location   *time.Location
}

// Allows reports whether t falls inside the window.
func (w *Window) Allows(t time.Time) bool {
	if w == nil {
		return true
	}

	loc := w.Location
	if loc == nil {
		loc = time.Local
	}
	t = t.In(loc)

	if len(w.Days) > 0 && !containsWeekday(w.Days, t.Weekday()) {
		return false
	}

	start, ok1 := parseHHMM(w.Start)
	end, ok2 := parseHHMM(w.End)
	if !ok1 || !ok2 {
		return false // fail closed on misconfiguration
	}

	cur := t.Hour()*60 + t.Minute()

	if start < end {
		// Same-day window: [start, end).
		return cur >= start && cur < end
	}
	// Wrapping window (end <= start): [start, 24:00) ∪ [00:00, end).
	return cur >= start || cur < end
}

func containsWeekday(days []time.Weekday, d time.Weekday) bool {
	for _, x := range days {
		if x == d {
			return true
		}
	}
	return false
}

// parseHHMM parses "HH:MM" into minutes-since-midnight. ok is false on any
// malformed input.
func parseHHMM(s string) (minutes int, ok bool) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 {
		return 0, false
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, false
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// guardTransport is an http.RoundTripper that enforces, in order: the kill
// switch, the scan window, scope, and a per-host request-rate limit. Only
// requests that pass every gate are handed to the base transport.
type guardTransport struct {
	base  http.RoundTripper
	scope core.Scope
	rps   int
	win   *Window
	kill  *KillSwitch

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	now      func() time.Time // injectable clock for tests
}

// newGuardTransport wraps base with the guard gates. If base is nil,
// http.DefaultTransport is used. If rps <= 0, per-host rate limiting is
// disabled. A nil win allows all times; a nil kill is treated as never killed.
func newGuardTransport(base http.RoundTripper, scope core.Scope, rps int,
	win *Window, kill *KillSwitch) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &guardTransport{
		base:     base,
		scope:    scope,
		rps:      rps,
		win:      win,
		kill:     kill,
		limiters: make(map[string]*rate.Limiter),
		now:      time.Now,
	}
}

// RoundTrip implements http.RoundTripper.
func (g *guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 1. Kill switch — cheapest and highest priority.
	if g.kill.Killed() {
		return nil, ErrKilled
	}

	// 2. Scan window.
	if !g.win.Allows(g.now()) {
		return nil, ErrOutsideWindow
	}

	// 3. Scope.
	if !g.scope.Allows(req.URL) {
		return nil, ErrOutOfScope
	}

	// 4. Per-host rate limit. Wait respects the request context so a
	// cancelled or timed-out scan unblocks immediately.
	if g.rps > 0 {
		lim := g.limiterFor(req.URL.Hostname())
		if err := lim.Wait(req.Context()); err != nil {
			return nil, err
		}
		// Re-check the kill switch after potentially blocking on the limiter.
		if g.kill.Killed() {
			return nil, ErrKilled
		}
	}

	return g.base.RoundTrip(req)
}

// limiterFor returns the per-host limiter, creating it on first use.
func (g *guardTransport) limiterFor(host string) *rate.Limiter {
	g.mu.Lock()
	defer g.mu.Unlock()
	lim, ok := g.limiters[host]
	if !ok {
		burst := g.rps
		if burst < 1 {
			burst = 1
		}
		lim = rate.NewLimiter(rate.Limit(g.rps), burst)
		g.limiters[host] = lim
	}
	return lim
}
