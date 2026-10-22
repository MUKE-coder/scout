package engine

import (
	"fmt"

	"github.com/MUKE-coder/scout/core"
)

// Decision says whether one check will run in a scan, and why not if not.
type Decision struct {
	Check  core.Check
	Run    bool
	Reason string // empty when Run is true
}

// Policy is the mode decision for one scan: the requested mode, the cap
// imposed by the environment and opt-in, and the effective mode.
type Policy struct {
	Requested core.Mode
	Cap       core.Mode
	CapReason string
	Effective core.Mode
}

// NewPolicy caps the requested mode by the target's environment and opt-in.
func NewPolicy(t core.Target, requested core.Mode) Policy {
	p := Policy{Requested: requested, Cap: t.Environment.Cap(t.AllowActive)}
	p.CapReason = capReason(t)
	p.Effective = min(requested, p.Cap)
	return p
}

// lower reduces the cap (never raises it) and records why.
func (p *Policy) lower(to core.Mode, reason string) {
	if to < p.Cap {
		p.Cap, p.CapReason = to, reason
		p.Effective = min(p.Requested, p.Cap)
	}
}

// Decide applies the policy to one check.
func (p Policy) Decide(c core.Check) Decision {
	switch {
	case c.Mode() > p.Cap:
		return Decision{Check: c, Reason: fmt.Sprintf("needs %s mode; capped at %s (%s)", c.Mode(), p.Cap, p.CapReason)}
	case c.Mode() > p.Requested:
		return Decision{Check: c, Reason: fmt.Sprintf("needs %s mode; scan requested %s", c.Mode(), p.Requested)}
	}
	return Decision{Check: c, Run: true}
}

func capReason(t core.Target) string {
	env := t.Environment
	switch env {
	case core.EnvDev:
		return "dev allows every mode"
	case core.EnvStaging:
		if t.AllowActive {
			return "staging with per-target opt-in"
		}
		return "staging without per-target opt-in"
	default:
		if t.AllowActive {
			return "prod with per-target opt-in; intrusive is never allowed in prod"
		}
		return "prod without per-target opt-in"
	}
}
