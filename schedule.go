package scout

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
)

// Schedule runs scans on a cron schedule.
type Schedule struct {
	Name string `json:"name" yaml:"name"`
	// Cron is a standard 5-field expression ("0 3 * * *") or a descriptor
	// such as "@daily".
	Cron string `json:"cron" yaml:"cron"`
	// Timezone is an IANA name; empty means local time.
	Timezone string `json:"timezone,omitempty" yaml:"timezone"`
	// Targets are target names; empty means every configured target.
	Targets []string `json:"targets,omitempty" yaml:"targets"`
	// Mode caps this schedule (default safe). The environment caps it further.
	Mode string `json:"mode,omitempty" yaml:"mode"`
}

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// spec returns the cron spec with its timezone applied.
func (s Schedule) spec() string {
	if s.Timezone != "" {
		return "CRON_TZ=" + s.Timezone + " " + s.Cron
	}
	return s.Cron
}

// mode returns the schedule's mode cap, defaulting to safe.
func (s Schedule) mode() (core.Mode, error) {
	if s.Mode == "" {
		return core.ModeSafe, nil
	}
	return core.ParseMode(s.Mode)
}

// validateSchedules checks every schedule against the configured targets.
func validateSchedules(schedules []Schedule, targets []core.Target) error {
	names := map[string]bool{}
	known := map[string]bool{}
	for _, t := range targets {
		known[t.Name] = true
	}
	for _, s := range schedules {
		if s.Name == "" {
			return fmt.Errorf("schedule: every schedule needs a name")
		}
		if names[s.Name] {
			return fmt.Errorf("schedule %q: duplicate name", s.Name)
		}
		names[s.Name] = true
		if _, err := cronParser.Parse(s.spec()); err != nil {
			return fmt.Errorf("schedule %q: invalid cron %q: %w", s.Name, s.Cron, err)
		}
		if _, err := s.mode(); err != nil {
			return fmt.Errorf("schedule %q: %w", s.Name, err)
		}
		for _, t := range s.Targets {
			if !known[t] {
				return fmt.Errorf("schedule %q: unknown target %q", s.Name, t)
			}
		}
		if len(targets) == 0 {
			return fmt.Errorf("schedule %q: no targets are configured", s.Name)
		}
	}
	return nil
}

// ScheduleInfo is a schedule with its next run, for the dashboard.
type ScheduleInfo struct {
	Schedule
	Next time.Time `json:"next"`
}

// scheduler runs configured schedules through the engine.
type scheduler struct {
	cron    *cron.Cron
	entries map[string]cron.EntryID
	mu      sync.Mutex
}

// newScheduler registers schedules; run is called with the schedule's
// targets and mode cap each time it fires. Overlapping runs of one schedule
// are skipped.
func newScheduler(schedules []Schedule, targets []core.Target, log *slog.Logger,
	run func(ctx context.Context, t core.Target, mode core.Mode)) (*scheduler, func(context.Context), error) {
	if err := validateSchedules(schedules, targets); err != nil {
		return nil, nil, err
	}
	c := cron.New(cron.WithParser(cronParser), cron.WithChain(cron.Recover(cron.DiscardLogger)))
	s := &scheduler{cron: c, entries: map[string]cron.EntryID{}}
	var ctx context.Context = context.Background()
	var ctxMu sync.Mutex

	for _, sch := range schedules {
		sch := sch
		mode, _ := sch.mode()
		var running sync.Mutex
		id, err := c.AddFunc(sch.spec(), func() {
			if !running.TryLock() {
				log.Warn("schedule still running; skipping this run", "schedule", sch.Name)
				return
			}
			defer running.Unlock()
			ctxMu.Lock()
			runCtx := ctx
			ctxMu.Unlock()
			log.Info("scheduled scan starting", "schedule", sch.Name, "mode", mode)
			for _, t := range pick(targets, sch.Targets) {
				if runCtx.Err() != nil {
					return
				}
				run(runCtx, t, mode)
			}
		})
		if err != nil {
			return nil, nil, fmt.Errorf("schedule %q: %w", sch.Name, err)
		}
		s.entries[sch.Name] = id
	}

	start := func(lifeCtx context.Context) {
		ctxMu.Lock()
		ctx = lifeCtx
		ctxMu.Unlock()
		c.Start()
		<-lifeCtx.Done()
		<-c.Stop().Done() // wait for running jobs
	}
	return s, start, nil
}

// info lists schedules with their next run time.
func (s *scheduler) info(schedules []Schedule) []ScheduleInfo {
	out := make([]ScheduleInfo, 0, len(schedules))
	for _, sch := range schedules {
		si := ScheduleInfo{Schedule: sch}
		if s != nil {
			s.mu.Lock()
			if id, ok := s.entries[sch.Name]; ok {
				si.Next = s.cron.Entry(id).Next
			}
			s.mu.Unlock()
			if si.Next.IsZero() { // not started yet: compute from the spec
				if sched, err := cronParser.Parse(sch.spec()); err == nil {
					si.Next = sched.Next(time.Now())
				}
			}
		}
		out = append(out, si)
	}
	return out
}

func pick(targets []core.Target, names []string) []core.Target {
	if len(names) == 0 {
		return targets
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []core.Target
	for _, t := range targets {
		if want[t.Name] {
			out = append(out, t)
		}
	}
	return out
}

// runScheduled is the scheduler's run function for a Scout instance.
func (s *Scout) runScheduled(ctx context.Context, t core.Target, mode core.Mode) {
	res, err := s.engine.Run(ctx, engine.Request{Target: t, Mode: mode})
	if err != nil {
		s.log.Warn("scheduled scan not run", "target", t.Name, "err", err)
		return
	}
	s.log.Info("scheduled scan finished", "target", t.Name, "scan", res.ID, "grade", res.Grade, "findings", len(res.Findings))
}
