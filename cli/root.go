package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/MUKE-coder/scout"
	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/storage"
)

// NewRootCmd builds the scout command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "scout",
		Short:         "Point it at your app. See every way in.",
		Long:          "Scout is a self-hosted vulnerability scanner and attack-surface mapper for developers.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().String("log-level", "info", "log level: debug, info, warn, error")
	root.PersistentFlags().String("log-format", "text", "log format: text or json")
	root.PersistentFlags().String("config", "", "path to scout.yaml")
	root.PersistentFlags().String("color", "auto", "color output: auto, always, never")

	root.AddCommand(newInitCmd(), newScanCmd(), newServeCmd(), newCICmd(), newLabCmd(), newSBOMCmd(), newDiffCmd(), newOwnershipCmd(), newPruneCmd(), newReportCmd(), newVersionCmd())
	return root
}

func newServeCmd() *cobra.Command {
	var (
		addr string
		db   string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the dashboard and scheduled scans",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, addr, db)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":9090", "listen address")
	cmd.Flags().StringVar(&db, "db", "scout.db", "SQLite database path")
	return cmd
}

func newOwnershipCmd() *cobra.Command {
	var target string
	cmd := &cobra.Command{
		Use:   "ownership",
		Short: "Print the token that proves you own a target (required for active scans)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			t := core.Target{Name: target, URL: target, Environment: core.EnvProd}
			if err := t.Validate(); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if t.IsLocal() {
				fmt.Fprintf(out, "%s is local: no ownership proof is needed.\n", t.Host())
				return nil
			}
			// Use the same key scans verify with, or the token would not match.
			explicit, _ := cmd.Flags().GetString("config")
			cfg, err := scout.LoadConfig(scout.FindConfig(explicit), os.Getenv)
			if err != nil {
				return err
			}
			host := t.Host()
			token := engine.OwnershipToken([]byte(cfg.SigningKey), host)
			fmt.Fprintf(out, "Ownership token for %s:\n\n  %s\n\n", host, token)
			fmt.Fprintf(out, "Publish it in one of these places before running an active scan:\n")
			fmt.Fprintf(out, "  DNS TXT on _scout-verify.%s   %s%s\n", host, engine.TXTPrefix, token)
			fmt.Fprintf(out, "  DNS TXT on %s                 %s%s\n", host, engine.TXTPrefix, token)
			fmt.Fprintf(out, "  File   %s://%s%s   containing the token\n", "https", host, engine.WellKnownPath)
			return nil
		},
	}
	cmd.Flags().StringVarP(&target, "target", "t", "", "target URL")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}

func newPruneCmd() *cobra.Command {
	var (
		db        string
		retention time.Duration
	)
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Delete scans older than the retention period",
		RunE: func(cmd *cobra.Command, _ []string) error {
			explicit, _ := cmd.Flags().GetString("config")
			cfg, err := scout.LoadConfig(scout.FindConfig(explicit), os.Getenv)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("db") || cfg.DBPath == "" {
				cfg.DBPath = db
			}
			if cmd.Flags().Changed("retention") {
				cfg.Retention = retention
			}
			store, err := storage.OpenSQLite(cfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()
			n, err := scout.Prune(cmd.Context(), store, cfg.Retention, time.Now())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %d scan(s) older than %s.\n", n, cfg.Retention)
			return nil
		},
	}
	cmd.Flags().StringVar(&db, "db", "scout.db", "SQLite file with scan history")
	cmd.Flags().DurationVar(&retention, "retention", scout.DefaultRetention, "keep scans newer than this (e.g. 720h)")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Scout version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "scout %s\n", scout.Version)
		},
	}
}
