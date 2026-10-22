package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/report"
	"github.com/MUKE-coder/scout/scoring"
	"github.com/MUKE-coder/scout/storage"
)

// Exit codes. Any other error exits with ExitError.
const (
	ExitOK         = 0
	ExitGateFailed = 1
	ExitError      = 2
)

// GateError means the CI gate failed: findings at or above the threshold.
type GateError struct {
	Count     int
	Threshold core.Severity
}

func (e *GateError) Error() string {
	return fmt.Sprintf("CI gate failed: %d finding(s) at or above %s", e.Count, e.Threshold)
}

// ExitCode maps an error returned by the root command to a process exit code.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var gate *GateError
	if errors.As(err, &gate) {
		return ExitGateFailed
	}
	return ExitError
}

func newCICmd() *cobra.Command {
	var (
		f       scanFlags
		failOn  string
		newOnly bool
	)
	cmd := &cobra.Command{
		Use:   "ci",
		Short: "Scan in CI and fail the build on findings",
		Long: `Scan in CI and fail the build on findings.

Exit codes: 0 gate passed, 1 gate failed, 2 error.
With --new-only, only findings that are new or regressed since the target's
previous scan count. With no previous scan, every finding counts as new.`,
		Example: `  scout ci --repo . --fail-on high --new-only --sarif out.sarif`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			threshold, err := core.ParseSeverity(failOn)
			if err != nil {
				return err
			}
			cfg, err := f.config()
			if err != nil {
				return err
			}
			store, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer store.Close()

			ctx := cmd.Context()
			eng := newEngine(cfg, store)
			var results []report.Result
			failing := 0
			for _, t := range cfg.Targets {
				prev, prevErr := store.LatestScan(ctx, t.Name)
				if prevErr != nil && !errors.Is(prevErr, storage.ErrNotFound) {
					return prevErr
				}
				res, err := eng.Run(ctx, engine.Request{Target: t, Mode: cfg.Mode})
				if err != nil {
					return err
				}
				results = append(results, report.Build(res, scoring.Options{Criticality: cfg.Criticality}))

				counted := openFindings(res.Findings)
				if newOnly {
					if prevErr != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "note: no previous scan of %s; every finding counts as new\n", t.Name)
					} else {
						d := report.DiffScans(prev, res, seenBefore(ctx, store, prev.StartedAt))
						counted = append(d.New, d.Regressed...)
					}
				}
				for _, fd := range counted {
					if fd.Severity >= threshold {
						failing++
					}
				}
			}
			if err := writeOutputs(cmd, f, results); err != nil {
				return err
			}

			scope := "open"
			if newOnly {
				scope = "new or regressed"
			}
			if failing > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "FAIL: %d %s finding(s) at or above %s\n", failing, scope, threshold)
				return &GateError{Count: failing, Threshold: threshold}
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "PASS: no %s findings at or above %s\n", scope, threshold)
			return nil
		},
	}
	f.bind(cmd)
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "fail when a finding is at or above this severity")
	cmd.Flags().BoolVar(&newOnly, "new-only", false, "only count findings new or regressed since the last scan")
	return cmd
}

func openFindings(fs []core.Finding) []core.Finding {
	var out []core.Finding
	for _, f := range fs {
		if f.Status == "" || f.Status == core.StatusOpen {
			out = append(out, f)
		}
	}
	return out
}
