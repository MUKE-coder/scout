package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/selftest"
	"github.com/MUKE-coder/scout/storage"
)

// Defaults used when Options leave a field zero.
const (
	DefaultConcurrency  = 4
	DefaultCheckTimeout = 60 * time.Second
)

// Options configure an Engine.
type Options struct {
	// Concurrency is how many checks run at once.
	Concurrency int
	// CheckTimeout bounds each check run.
	CheckTimeout time.Duration
	Logger       *slog.Logger
	// Now is the clock; tests override it.
	Now func() time.Time

	// Scope limits what checks may touch. Empty Hosts means only the
	// target's own host.
	Scope core.Scope
	// RateLimit is max requests per second per host; <= 0 disables it.
	RateLimit int
	// Window restricts when scans may run; nil allows any time.
	Window *Window
	// Kill is the global kill switch; nil means none.
	Kill *KillSwitch
	// Transport is the base HTTP transport; nil uses http.DefaultTransport.
	Transport http.RoundTripper
	// SigningKey signs the X-Scout-Scan header. Empty generates a random
	// key per engine, which Sentinel cannot verify; set it to share one.
	SigningKey []byte
	// Verifier proves target ownership before Active mode on non-local
	// hosts. Nil uses DNS and the well-known file, keyed by SigningKey.
	Verifier *Verifier
	// Store persists scans and supplies history for FirstSeen and status
	// carry-over. Nil keeps results in memory only.
	Store storage.Store
	// Bus receives scan progress and finding events. Nil disables events.
	Bus *Bus
}

// Engine runs scans. It is safe for concurrent use.
type Engine struct {
	reg  *core.Registry
	opts Options
	log  *slog.Logger
}

// New returns an engine that draws checks from reg.
func New(reg *core.Registry, opts Options) *Engine {
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.CheckTimeout <= 0 {
		opts.CheckTimeout = DefaultCheckTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Verifier == nil {
		// Use the caller's key only: a random per-run key would make the
		// ownership token change on every run.
		opts.Verifier = NewVerifier(opts.SigningKey)
	}
	if len(opts.SigningKey) == 0 {
		opts.SigningKey = selftest.NewKey()
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Engine{reg: reg, opts: opts, log: log}
}

// Request describes one scan.
type Request struct {
	Target core.Target
	// Mode is the requested mode; the engine caps it by policy.
	Mode core.Mode
	// Checks restricts the scan to these check IDs (used by "verify fix").
	// Empty means every registered check.
	Checks []string
}

// ErrCheckTimeout is recorded when a check exceeds its timeout.
var ErrCheckTimeout = errors.New("check timed out")

// Run executes a scan and returns its result. Check failures are recorded
// in the result, never returned: only a broken request fails Run.
func (e *Engine) Run(ctx context.Context, req Request) (core.ScanResult, error) {
	if err := req.Target.Validate(); err != nil {
		return core.ScanResult{}, err
	}
	if e.opts.Kill.Killed() {
		return core.ScanResult{}, ErrKilled
	}
	if !e.opts.Window.Allows(e.opts.Now()) {
		return core.ScanResult{}, ErrOutsideWindow
	}
	scanID := NewScanID()
	client := e.client(req.Target, scanID)
	ctx = core.WithHTTPClient(ctx, client)
	policy := e.policy(ctx, req, client)
	res := core.ScanResult{
		ID:        scanID,
		Target:    req.Target,
		Mode:      policy.Effective,
		StartedAt: e.opts.Now(),
	}
	var run []core.Check
	for _, d := range e.decide(policy, req.Checks) {
		if d.Run {
			run = append(run, d.Check)
			continue
		}
		res.Skipped = append(res.Skipped, core.SkippedCheck{CheckID: d.Check.ID(), Mode: d.Check.Mode(), Reason: d.Reason})
	}
	e.log.Info("scan starting", "scan", res.ID, "target", req.Target.Name,
		"mode", policy.Effective, "run", len(run), "skipped", len(res.Skipped))
	e.opts.Bus.Publish(Event{Type: EventScanStarted, ScanID: res.ID, Time: res.StartedAt, Total: len(run)})
	res.Findings, res.Errors = e.runChecks(ctx, res.ID, req.Target, run)
	res.FinishedAt = e.opts.Now()
	e.finish(ctx, &res)
	return res, nil
}

// client builds the guarded HTTP client for one scan. Scope defaults to the
// target's own host so it is never wider than what the user pointed at.
// Requests that pass the guard are signed with the self-test header.
func (e *Engine) client(t core.Target, scanID string) *http.Client {
	scope := e.opts.Scope
	if len(scope.Hosts) == 0 && t.Host() != "" {
		scope.Hosts = []string{t.Host()}
	}
	signer := &selftest.Transport{Base: e.opts.Transport, Key: e.opts.SigningKey, ScanID: scanID, Now: e.opts.Now}
	return &http.Client{Transport: newGuardTransport(signer, scope, e.opts.RateLimit, e.opts.Window, e.opts.Kill)}
}

// policy caps the requested mode by environment and opt-in, then requires
// proven ownership before Active or Intrusive mode on a non-local host.
// Run and Plan both use it, so a plan always matches the real scan.
func (e *Engine) policy(ctx context.Context, req Request, client *http.Client) Policy {
	p := NewPolicy(req.Target, req.Mode)
	if p.Effective >= core.ModeActive && !req.Target.IsLocal() {
		if _, err := e.opts.Verifier.Verify(ctx, req.Target, client); err != nil {
			p.lower(core.ModeSafe, err.Error())
		}
	}
	return p
}

// decide applies the policy to every selected check.
func (e *Engine) decide(p Policy, ids []string) []Decision {
	checks := e.selectChecks(ids)
	out := make([]Decision, len(checks))
	for i, c := range checks {
		out[i] = p.Decide(c)
	}
	return out
}

// selectChecks returns the registered checks, restricted to ids if given.
func (e *Engine) selectChecks(ids []string) []core.Check {
	if len(ids) == 0 {
		return e.reg.All()
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	return e.reg.Filter(func(c core.Check) bool { return want[c.ID()] })
}

type checkOutcome struct {
	id       string
	findings []core.Finding
	err      error
}

// runChecks runs checks on a bounded worker pool. Results are returned in
// check-ID order so scans are deterministic regardless of scheduling.
func (e *Engine) runChecks(ctx context.Context, scanID string, t core.Target, checks []core.Check) ([]core.Finding, []core.CheckError) {
	jobs := make(chan core.Check)
	outcomes := make(chan checkOutcome, len(checks))

	var wg sync.WaitGroup
	var done atomic.Int32
	workers := min(e.opts.Concurrency, max(len(checks), 1))
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				fs, err := e.runOne(ctx, c, t)
				outcomes <- checkOutcome{id: c.ID(), findings: fs, err: err}
				ev := Event{Type: EventCheckFinished, ScanID: scanID, Time: e.opts.Now(), CheckID: c.ID(),
					Count: len(fs), Total: len(checks), Done: int(done.Add(1))}
				if err != nil {
					ev.Error = err.Error()
				}
				e.opts.Bus.Publish(ev)
			}
		}()
	}

feed:
	for _, c := range checks {
		select {
		case jobs <- c:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	close(outcomes)

	var all []checkOutcome
	for o := range outcomes {
		all = append(all, o)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].id < all[j].id })

	var findings []core.Finding
	var errs []core.CheckError
	for _, o := range all {
		if o.err != nil {
			errs = append(errs, core.CheckError{CheckID: o.id, Error: o.err.Error()})
		}
		findings = append(findings, o.findings...)
	}
	if ctx.Err() != nil {
		errs = append(errs, core.CheckError{CheckID: "engine", Error: "scan cancelled: " + ctx.Err().Error()})
	}
	return findings, errs
}

// runOne runs a single check with a timeout and panic recovery. A check
// that ignores its context is abandoned at the deadline so it can never
// hang the scan.
func (e *Engine) runOne(parent context.Context, c core.Check, t core.Target) ([]core.Finding, error) {
	ctx, cancel := context.WithTimeout(parent, e.opts.CheckTimeout)
	defer cancel()

	done := make(chan checkOutcome, 1) // buffered: an abandoned check must not block forever
	go func() {
		defer func() {
			if r := recover(); r != nil {
				e.log.Error("check panicked", "check", c.ID(), "panic", r, "stack", string(debug.Stack()))
				done <- checkOutcome{err: fmt.Errorf("check panicked: %v", r)}
			}
		}()
		fs, err := c.Run(ctx, t)
		done <- checkOutcome{findings: fs, err: err}
	}()

	select {
	case o := <-done:
		for i := range o.findings {
			o.findings[i].CheckID = c.ID()
			o.findings[i].Normalize()
		}
		return o.findings, o.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && parent.Err() == nil {
			return nil, fmt.Errorf("%w after %s", ErrCheckTimeout, e.opts.CheckTimeout)
		}
		return nil, ctx.Err()
	}
}

// NewScanID returns a random 128-bit scan identifier.
func NewScanID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b[:])
}
