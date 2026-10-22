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

	root.AddCommand(newScanCmd(), newServeCmd(), newCICmd(), newDiffCmd(), newVersionCmd())
	return root
}

// scanFlags are shared by scan and ci.
type scanFlags struct {
	targets []string
	repo    string
	mode    string
	env     string
	dryRun  bool
	optIn   bool
	json    bool
	sarif   string
}

func (f *scanFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringSliceVarP(&f.targets, "target", "t", nil, "target URL (repeatable)")
	cmd.Flags().StringVar(&f.repo, "repo", "", "local repo path for code and supply-chain checks")
	cmd.Flags().StringVarP(&f.mode, "mode", "m", "safe", "scan mode: passive, safe, active, intrusive")
	cmd.Flags().StringVarP(&f.env, "env", "e", "dev", "environment: dev, staging, prod (caps the mode)")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "print what would run and run nothing")
	cmd.Flags().BoolVar(&f.optIn, "allow-active", false, "per-target opt-in: allows active in prod and intrusive in staging")
	cmd.Flags().BoolVar(&f.json, "json", false, "print results as JSON")
	cmd.Flags().StringVar(&f.sarif, "sarif", "", "write SARIF to this file")
}

// config validates the flags and turns them into a scout.Config.
func (f *scanFlags) config() (scout.Config, error) {
	mode, err := core.ParseMode(f.mode)
	if err != nil {
		return scout.Config{}, err
	}
	env, err := core.ParseEnvironment(f.env)
	if err != nil {
		return scout.Config{}, err
	}
	opts := []scout.Option{scout.WithEnvironment(env), scout.WithMode(mode)}
	for _, t := range f.targets {
		opts = append(opts, scout.WithTarget(t))
	}
	cfg, err := scout.NewConfig(opts...)
	if err != nil {
		return cfg, err
	}
	if f.repo != "" {
		cfg.Targets = append(cfg.Targets, core.Target{Name: f.repo, Repo: f.repo, Environment: env})
	}
	for i := range cfg.Targets {
		cfg.Targets[i].AllowActive = f.optIn
	}
	if len(cfg.Targets) == 0 {
		return cfg, fmt.Errorf("nothing to scan: pass --target and/or --repo")
	}
	return cfg, nil
}

func newScanCmd() *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a URL and/or a repo",
		Example: `  scout scan --target http://localhost:8080 --repo . --mode active
  scout scan --target https://example.com --mode safe`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := f.config()
			if err != nil {
				return err
			}
			eng := engine.New(core.DefaultRegistry, engine.Options{
				Concurrency:  cfg.Concurrency,
				CheckTimeout: cfg.CheckTimeout,
				RateLimit:    cfg.RateLimit,
				Scope:        cfg.Scope,
			})
			out := cmd.OutOrStdout()
			for _, t := range cfg.Targets {
				req := engine.Request{Target: t, Mode: cfg.Mode}
				if f.dryRun {
					p, err := eng.Plan(req)
					if err != nil {
						return err
					}
					if err := p.Render(out); err != nil {
						return err
					}
					fmt.Fprintln(out)
					continue
				}
				res, err := eng.Run(cmd.Context(), req)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "%s: mode %s, %d findings, %d skipped, %d errors\n",
					t.Name, res.Mode, len(res.Findings), len(res.Skipped), len(res.Errors))
			}
			return nil
		},
	}
	f.bind(cmd)
	return cmd
}

func newCICmd() *cobra.Command {
	var (
		f       scanFlags
		failOn  string
		newOnly bool
	)
	cmd := &cobra.Command{
		Use:     "ci",
		Short:   "Scan in CI and fail the build on findings",
		Example: `  scout ci --repo . --fail-on high --new-only --sarif out.sarif`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := core.ParseSeverity(failOn); err != nil {
				return err
			}
			if _, err := f.config(); err != nil {
				return err
			}
			return errNotImplemented("ci", 4)
		},
	}
	f.bind(cmd)
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "fail when a finding is at or above this severity")
	cmd.Flags().BoolVar(&newOnly, "new-only", false, "only consider findings new since the last scan")
	return cmd
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

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Scout version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "scout %s\n", scout.Version)
		},
	}
}
