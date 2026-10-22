package core

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Check is one pluggable security test. Collectors implement it and register
// into a Registry; the engine selects checks whose Mode fits the environment.
type Check interface {
	// ID is stable and namespaced: "tls.weak-protocols", "app.sqli".
	ID() string
	Category() Category
	// Mode is the most aggressive mode this check uses.
	Mode() Mode
	Run(ctx context.Context, t Target) ([]Finding, error)
}

// Describer is optionally implemented by checks to explain themselves in
// plan (dry-run) output and the dashboard.
type Describer interface {
	Description() string
}

// Registry holds the checks available to a scan. It is safe for concurrent use.
type Registry struct {
	mu     sync.RWMutex
	checks map[string]Check
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{checks: make(map[string]Check)}
}

// Register adds a check. IDs must be unique and non-empty.
func (r *Registry) Register(c Check) error {
	if c == nil || c.ID() == "" {
		return fmt.Errorf("register: check must have a non-empty ID")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.checks[c.ID()]; dup {
		return fmt.Errorf("register: duplicate check ID %q", c.ID())
	}
	r.checks[c.ID()] = c
	return nil
}

// MustRegister is Register for init-time registration; it panics on error.
func (r *Registry) MustRegister(c Check) {
	if err := r.Register(c); err != nil {
		panic(err)
	}
}

// Get returns a check by ID.
func (r *Registry) Get(id string) (Check, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.checks[id]
	return c, ok
}

// All returns every check sorted by ID, so scans and plans are deterministic.
func (r *Registry) All() []Check {
	return r.Filter(nil)
}

// Filter returns the checks for which keep returns true, sorted by ID. A nil
// keep returns all checks.
func (r *Registry) Filter(keep func(Check) bool) []Check {
	r.mu.RLock()
	out := make([]Check, 0, len(r.checks))
	for _, c := range r.checks {
		if keep == nil || keep(c) {
			out = append(out, c)
		}
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Len returns the number of registered checks.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.checks)
}

// DefaultRegistry is where built-in collectors register their checks.
var DefaultRegistry = NewRegistry()

// Register adds a check to DefaultRegistry, panicking on a duplicate ID.
// Collectors call it from init().
func Register(c Check) { DefaultRegistry.MustRegister(c) }

// CheckFunc adapts a plain function into a Check. Handy for small native
// checks and tests.
type CheckFunc struct {
	CheckID       string
	CheckCategory Category
	CheckMode     Mode
	Desc          string
	Fn            func(ctx context.Context, t Target) ([]Finding, error)
}

func (c CheckFunc) ID() string          { return c.CheckID }
func (c CheckFunc) Category() Category  { return c.CheckCategory }
func (c CheckFunc) Mode() Mode          { return c.CheckMode }
func (c CheckFunc) Description() string { return c.Desc }
func (c CheckFunc) Run(ctx context.Context, t Target) ([]Finding, error) {
	if c.Fn == nil {
		return nil, nil
	}
	return c.Fn(ctx, t)
}
