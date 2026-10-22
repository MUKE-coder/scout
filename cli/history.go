package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/report"
	"github.com/MUKE-coder/scout/storage"
)

// seenBefore reports whether a fingerprint appeared in any scan that ended
// before the cutoff, which is how a returning finding counts as regressed.
func seenBefore(ctx context.Context, store storage.Store, cutoff time.Time) func(string) bool {
	return func(fingerprint string) bool {
		fs, err := store.ListFindings(ctx, storage.FindingFilter{Fingerprint: fingerprint})
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
}

// resolveScan finds a scan by full ID or unique ID prefix.
func resolveScan(ctx context.Context, store storage.Store, ref string) (core.ScanResult, error) {
	if s, err := store.GetScan(ctx, ref); err == nil {
		return s, nil
	} else if !errors.Is(err, storage.ErrNotFound) {
		return s, err
	}
	scans, err := store.ListScans(ctx, 0)
	if err != nil {
		return core.ScanResult{}, err
	}
	var match []string
	for _, s := range scans {
		if strings.HasPrefix(s.ID, ref) {
			match = append(match, s.ID)
		}
	}
	switch len(match) {
	case 0:
		return core.ScanResult{}, fmt.Errorf("no scan matches %q", ref)
	case 1:
		return store.GetScan(ctx, match[0])
	}
	return core.ScanResult{}, fmt.Errorf("%q matches %d scans; use more characters", ref, len(match))
}

func newDiffCmd() *cobra.Command {
	var (
		db     string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:     "diff <scan-a> <scan-b>",
		Short:   "Show new, fixed and regressed findings between two scans",
		Example: "  scout diff 3f2a9c 9b1c04",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if db == "" {
				return fmt.Errorf("diff needs scan history: pass --db")
			}
			store, err := storage.OpenSQLite(db)
			if err != nil {
				return err
			}
			defer store.Close()
			ctx := cmd.Context()
			a, err := resolveScan(ctx, store, args[0])
			if err != nil {
				return err
			}
			b, err := resolveScan(ctx, store, args[1])
			if err != nil {
				return err
			}
			if a.StartedAt.After(b.StartedAt) {
				a, b = b, a // always diff older -> newer
			}
			if a.Target.Name != b.Target.Name {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: comparing different targets (%s vs %s)\n", a.Target.Name, b.Target.Name)
			}
			d := report.DiffScans(a, b, seenBefore(ctx, store, a.StartedAt))
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(d)
			}
			return report.PrettyDiff(cmd.OutOrStdout(), d, useColor(cmd))
		},
	}
	cmd.Flags().StringVar(&db, "db", "scout.db", "SQLite file with scan history")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the diff as JSON")
	return cmd
}
