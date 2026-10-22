package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/MUKE-coder/scout"
	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
)

// errNotImplemented marks commands whose behaviour lands in a later phase.
func errNotImplemented(cmd string, phase int) error {
	return fmt.Errorf("%s: not implemented yet (arrives in phase %d)", cmd, phase)
}

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

	root.AddCommand(newScanCmd(), newServeCmd(), newCICmd(), newDiffCmd(), newOwnershipCmd(), newVersionCmd())
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

func newDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <scan-a> <scan-b>",
		Short: "Show new, fixed and regressed findings between two scans",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errNotImplemented("diff", 4)
		},
	}
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
			host := t.Host()
			token := engine.OwnershipToken(nil, host)
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

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Scout version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "scout %s\n", scout.Version)
		},
	}
}
