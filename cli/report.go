package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/MUKE-coder/scout"
	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/report"
	"github.com/MUKE-coder/scout/scoring"
	"github.com/MUKE-coder/scout/storage"
)

func newReportCmd() *cobra.Command {
	var (
		db  string
		out string
	)
	cmd := &cobra.Command{
		Use:   "report [scan-id...]",
		Short: "Write a printable HTML report (latest scan of every target by default)",
		Long: `Write a self-contained HTML report. Open it in a browser and print to
save a PDF. Without scan IDs, the latest scan of every target is used.`,
		Example: "  scout report --out report.html\n  scout report 3f2a9c --out shop.html",
		RunE: func(cmd *cobra.Command, args []string) error {
			explicit, _ := cmd.Flags().GetString("config")
			cfg, err := scout.LoadConfig(scout.FindConfig(explicit), os.Getenv)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("db") || cfg.DBPath == "" {
				cfg.DBPath = db
			}
			store, err := storage.OpenSQLite(cfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			ctx := cmd.Context()
			var scans []core.ScanResult
			if len(args) > 0 {
				for _, ref := range args {
					sc, err := resolveScan(ctx, store, ref)
					if err != nil {
						return err
					}
					scans = append(scans, sc)
				}
			} else {
				all, err := store.ListScans(ctx, 0)
				if err != nil {
					return err
				}
				seen := map[string]bool{}
				for _, meta := range all { // newest first
					if seen[meta.Target.Name] {
						continue
					}
					seen[meta.Target.Name] = true
					sc, err := store.GetScan(ctx, meta.ID)
					if err != nil {
						return err
					}
					scans = append(scans, sc)
				}
			}
			if len(scans) == 0 {
				return fmt.Errorf("no scans in %s", cfg.DBPath)
			}

			results := make([]report.Result, 0, len(scans))
			for _, sc := range scans {
				results = append(results, report.Build(sc, scoring.Options{Criticality: cfg.Criticality}))
			}
			opts := report.HTMLOptions{Title: cfg.AppName + " security report", Version: scout.Version}
			if out == "" || out == "-" {
				return report.HTML(cmd.OutOrStdout(), results, opts)
			}
			file, err := os.Create(filepath.Clean(out))
			if err != nil {
				return err
			}
			if err := report.HTML(file, results, opts); err != nil {
				_ = file.Close() // the render error is the one to report
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Wrote %s (%d target(s)). Open it and print to save a PDF.\n", out, len(results))
			return nil
		},
	}
	cmd.Flags().StringVar(&db, "db", "scout.db", "SQLite file with scan history")
	cmd.Flags().StringVarP(&out, "out", "o", "", `output file ("-" or empty for stdout)`)
	return cmd
}
