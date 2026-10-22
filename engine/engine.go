package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/MUKE-coder/scout/core"
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
	policy := NewPolicy(req.Target, req.Mode)
	res := core.ScanResult{
		ID:        NewScanID(),
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
	res.Findings, res.Errors = e.runChecks(ctx, req.Target, run)
	res.FinishedAt = e.opts.Now()
	return res, nil
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
func (e *Engine) runChecks(ctx context.Context, t core.Target, checks []core.Check) ([]core.Finding, []core.CheckError) {
	jobs := make(chan core.Check)
	outcomes := make(chan checkOutcome, len(checks))

	var wg sync.WaitGroup
	workers := min(e.opts.Concurrency, max(len(checks), 1))
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				fs, err := e.runOne(ctx, c, t)
				outcomes <- checkOutcome{id: c.ID(), findings: fs, err: err}
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
