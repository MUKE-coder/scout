package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/MUKE-coder/scout"
	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/report"
	"github.com/MUKE-coder/scout/scoring"
	"github.com/MUKE-coder/scout/storage"
)

// scanFlags are shared by scan and ci.
type scanFlags struct {
	targets []string
	repo    string
	mode    string
	env     string
	db      string
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
	cmd.Flags().StringVar(&f.db, "db", "scout.db", `SQLite file for scan history ("" keeps nothing)`)
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "print what would run and run nothing")
	cmd.Flags().BoolVar(&f.optIn, "allow-active", false, "per-target opt-in: allows active in prod and intrusive in staging")
	cmd.Flags().BoolVar(&f.json, "json", false, "print results as JSON instead of the terminal report")
	cmd.Flags().StringVar(&f.sarif, "sarif", "", "also write SARIF 2.1.0 to this file")
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
	opts := []scout.Option{scout.WithEnvironment(env), scout.WithMode(mode), scout.WithDB(f.db)}
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

// openStore opens the configured history store, or memory-only when DBPath
// is empty.
func openStore(cfg scout.Config) (storage.Store, error) {
	if cfg.DBPath == "" {
		return storage.NewMemory(storage.DefaultMemoryCapacity), nil
	}
	return storage.OpenSQLite(cfg.DBPath)
}

// registry supplies the checks the CLI runs. Tests replace it.
var registry = core.DefaultRegistry

func newEngine(cfg scout.Config, store storage.Store) *engine.Engine {
	return engine.New(registry, engine.Options{
		Concurrency:  cfg.Concurrency,
		CheckTimeout: cfg.CheckTimeout,
		RateLimit:    cfg.RateLimit,
		Scope:        cfg.Scope,
		SigningKey:   []byte(cfg.SigningKey),
		Store:        store,
		Scoring:      scoring.Options{Criticality: cfg.Criticality},
	})
}

func newScanCmd() *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a URL and/or a repo",
		Example: `  scout scan --target http://localhost:8080 --repo . --mode active
  scout scan --target https://example.com --mode safe
  scout scan --target https://example.com --json > result.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := f.config()
			if err != nil {
				return err
			}
			if f.dryRun {
				return plan(cmd, cfg)
			}
			store, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer store.Close()

			eng := newEngine(cfg, store)
			var results []report.Result
			for _, t := range cfg.Targets {
				res, err := eng.Run(cmd.Context(), engine.Request{Target: t, Mode: cfg.Mode})
				if err != nil {
					return err
				}
				results = append(results, report.Build(res, scoring.Options{Criticality: cfg.Criticality}))
			}
			return writeOutputs(cmd, f, results)
		},
	}
	f.bind(cmd)
	return cmd
}

// plan prints the dry-run plan for every target.
func plan(cmd *cobra.Command, cfg scout.Config) error {
	eng := newEngine(cfg, nil)
	out := cmd.OutOrStdout()
	for _, t := range cfg.Targets {
		p, err := eng.Plan(cmd.Context(), engine.Request{Target: t, Mode: cfg.Mode})
		if err != nil {
			return err
		}
		if err := p.Render(out); err != nil {
			return err
		}
		fmt.Fprintln(out)
	}
	return nil
}

// writeOutputs prints JSON or the terminal report and writes SARIF if asked.
func writeOutputs(cmd *cobra.Command, f scanFlags, results []report.Result) error {
	out := cmd.OutOrStdout()
	if f.json {
		if err := report.JSON(out, scout.Version, results); err != nil {
			return err
		}
	} else {
		for _, r := range results {
			if err := report.Pretty(out, r, report.PrettyOptions{Color: useColor(cmd)}); err != nil {
				return err
			}
			fmt.Fprintln(out)
		}
	}
	if f.sarif != "" {
		if err := writeSARIF(f.sarif, results); err != nil {
			return fmt.Errorf("write SARIF: %w", err)
		}
	}
	return nil
}

func writeSARIF(path string, results []report.Result) error {
	file, err := os.Create(filepath.Clean(path))
	if err != nil {
		return err
	}
	if err := report.SARIF(file, scout.Version, results); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
