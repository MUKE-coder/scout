package engine

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/MUKE-coder/scout/core"
)

// PlanEntry is one check's fate in a planned scan.
type PlanEntry struct {
	CheckID     string        `json:"check_id"`
	Category    core.Category `json:"category"`
	Mode        core.Mode     `json:"mode"`
	Run         bool          `json:"run"`
	Reason      string        `json:"reason,omitempty"`
	Description string        `json:"description,omitempty"`
}

// Plan is what a scan would do, computed by the same policy code Run uses.
type Plan struct {
	Target    core.Target `json:"target"`
	Requested core.Mode   `json:"requested_mode"`
	Effective core.Mode   `json:"effective_mode"`
	CapReason string      `json:"cap_reason"`
	Entries   []PlanEntry `json:"entries"`
}

// Plan returns what Run would do for req without running any check. The
// only traffic it may send is the read-only ownership lookup (DNS TXT or the
// well-known file) that Run would also make before Active mode.
func (e *Engine) Plan(ctx context.Context, req Request) (Plan, error) {
	if err := req.Target.Validate(); err != nil {
		return Plan{}, err
	}
	policy := e.policy(ctx, req, e.client(req.Target, "plan-"+NewScanID()))
	p := Plan{Target: req.Target, Requested: policy.Requested, Effective: policy.Effective, CapReason: policy.CapReason}
	for _, d := range e.decide(policy, req.Checks) {
		entry := PlanEntry{
			CheckID: d.Check.ID(), Category: d.Check.Category(), Mode: d.Check.Mode(),
			Run: d.Run, Reason: d.Reason,
		}
		if ds, ok := d.Check.(core.Describer); ok {
			entry.Description = ds.Description()
		}
		p.Entries = append(p.Entries, entry)
	}
	return p, nil
}

// Counts returns how many checks would run and be skipped.
func (p Plan) Counts() (run, skipped int) {
	for _, e := range p.Entries {
		if e.Run {
			run++
		} else {
			skipped++
		}
	}
	return run, skipped
}

// Render writes the plan as a human-readable table.
func (p Plan) Render(w io.Writer) error {
	run, skipped := p.Counts()
	fmt.Fprintf(w, "Plan for %s (%s)\n", p.Target.Name, p.Target.Environment)
	fmt.Fprintf(w, "Mode: requested %s, effective %s (%s)\n", p.Requested, p.Effective, p.CapReason)
	fmt.Fprintf(w, "Checks: %d would run, %d skipped. No checks were run.\n\n", run, skipped)
	if len(p.Entries) == 0 {
		_, err := fmt.Fprintln(w, "No checks registered.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ACTION\tCHECK\tCATEGORY\tMODE\tREASON")
	for _, e := range p.Entries {
		action := "run"
		if !e.Run {
			action = "skip"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", action, e.CheckID, e.Category, e.Mode, e.Reason)
	}
	return tw.Flush()
}
