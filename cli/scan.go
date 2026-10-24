package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	targets      []string
	repo         string
	mode         string
	env          string
	db           string
	dryRun       bool
	optIn        bool
	json         bool
	sarif        string
	export       []string
	serve        bool
	serveAddr    string
	checkTimeout time.Duration
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
	cmd.Flags().StringSliceVar(&f.export, "export", nil, "also write report files here (scout-report.<ext>): any of md,html,txt,json (e.g. --export md,html)")
	cmd.Flags().BoolVar(&f.serve, "serve", false, "after the scan, open the dashboard (keeps running until Ctrl+C)")
	cmd.Flags().StringVar(&f.serveAddr, "serve-addr", ":9090", "address for the --serve dashboard")
	cmd.Flags().DurationVar(&f.checkTimeout, "check-timeout", 0, "max time per check (e.g. 120s); 0 keeps the default (60s). Raise it for slow targets")
}

// config validates the flags and turns them into a scout.Config.
//
// Precedence: defaults < scout.yaml < SCOUT_* environment < flags. A flag
// only overrides when it was actually passed.
func (f *scanFlags) config(cmd *cobra.Command) (scout.Config, error) {
	explicit, _ := cmd.Flags().GetString("config")
	cfg, err := scout.LoadConfig(scout.FindConfig(explicit), os.Getenv)
	if err != nil {
		return cfg, err
	}
	changed := cmd.Flags().Changed

	if changed("env") {
		env, err := core.ParseEnvironment(f.env)
		if err != nil {
			return cfg, err
		}
		cfg.Environment = env
		for i := range cfg.Targets {
			cfg.Targets[i].Environment = env
		}
	}
	if changed("mode") {
		mode, err := core.ParseMode(f.mode)
		if err != nil {
			return cfg, err
		}
		cfg.Mode = mode
	}
	if changed("db") || cfg.DBPath == "" {
		cfg.DBPath = f.db // the flag default (scout.db) applies when config sets none
	}
	if changed("check-timeout") {
		cfg.CheckTimeout = f.checkTimeout
	}
	if changed("target") {
		cfg.Targets = nil
		for _, u := range f.targets {
			t := core.Target{Name: u, URL: u, Environment: cfg.Environment}
			if err := t.Validate(); err != nil {
				return cfg, err
			}
			cfg.Targets = append(cfg.Targets, t)
		}
	}
	if f.repo != "" {
		cfg.Targets = append(cfg.Targets, core.Target{Name: f.repo, Repo: f.repo, Environment: cfg.Environment})
	}
	if changed("allow-active") {
		for i := range cfg.Targets {
			cfg.Targets[i].AllowActive = f.optIn
		}
	}
	if len(cfg.Targets) == 0 {
		return cfg, fmt.Errorf("nothing to scan: pass --target and/or --repo, or list targets in scout.yaml")
	}
	return cfg, cfg.Validate()
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

func newEngine(cfg scout.Config, store storage.Store) (*engine.Engine, error) {
	return newEngineWithBus(cfg, store, nil)
}

func newEngineWithBus(cfg scout.Config, store storage.Store, bus *engine.Bus) (*engine.Engine, error) {
	window, err := cfg.Window.EngineWindow()
	if err != nil {
		return nil, err
	}
	return engine.New(registry, engine.Options{
		Concurrency:  cfg.Concurrency,
		CheckTimeout: cfg.CheckTimeout,
		RateLimit:    cfg.RateLimit,
		Scope:        cfg.Scope,
		Window:       window,
		SigningKey:   []byte(cfg.SigningKey),
		Store:        store,
		Bus:          bus,
		Scoring:      scoring.Options{Criticality: cfg.Criticality},
	}), nil
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
			cfg, err := f.config(cmd)
			if err != nil {
				return err
			}
			if f.dryRun {
				return plan(cmd, cfg)
			}
			// Run the scan in a closure so its store is closed before --serve
			// opens the same database for the dashboard.
			results, err := runScan(cmd, f, cfg)
			if err != nil {
				return err
			}
			if err := writeOutputs(cmd, f, results); err != nil {
				return err
			}
			printDashboardHint(cmd, f, cfg, results)

			// --serve: hand straight off to the dashboard on the same DB.
			if f.serve {
				fmt.Fprintf(cmd.OutOrStdout(), "\nStarting the dashboard on %s …  (Ctrl+C to stop)\n", f.serveAddr)
				return runServe(cmd, f.serveAddr, cfg.DBPath)
			}
			return nil
		},
	}
	f.bind(cmd)
	return cmd
}

// runScan opens the history store, runs every target (with a live progress
// line), and returns the built results. The store is closed before returning,
// so a following --serve can open the same database.
func runScan(cmd *cobra.Command, f scanFlags, cfg scout.Config) ([]report.Result, error) {
	store, err := openStore(cfg)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	// A live progress line (stderr, terminal only) so the user sees what is
	// happening instead of an empty screen. Skipped for --json.
	var bus *engine.Bus
	var prog *progressReporter
	if !f.json {
		bus = engine.NewBus()
		prog = startProgress(bus, progressWriter, useColor(cmd))
	}
	defer func() {
		if prog != nil {
			prog.stop()
		}
	}()

	eng, err := newEngineWithBus(cfg, store, bus)
	if err != nil {
		return nil, err
	}
	var results []report.Result
	for _, t := range cfg.Targets {
		if prog != nil {
			prog.setTarget(t.Name)
		}
		res, err := eng.Run(cmd.Context(), engine.Request{Target: t, Mode: cfg.Mode})
		if err != nil {
			return nil, err
		}
		results = append(results, report.Build(res, scoring.Options{Criticality: cfg.Criticality}))
	}
	if prog != nil {
		prog.stop()
	}
	return results, nil
}

// plan prints the dry-run plan for every target.
func plan(cmd *cobra.Command, cfg scout.Config) error {
	eng, err := newEngine(cfg, nil)
	if err != nil {
		return err
	}
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

// printDashboardHint points the user at the dashboard, where the scan they
// just ran is waiting. Shown only for the human report (not --json) and only
// when the scan was saved to a DB the dashboard can read.
func printDashboardHint(cmd *cobra.Command, f scanFlags, cfg scout.Config, results []report.Result) {
	// With --serve we boot the dashboard right away, so no hint is needed.
	if f.json || f.serve || cfg.DBPath == "" || len(results) == 0 {
		return
	}
	out := cmd.OutOrStdout()
	color := useColor(cmd)
	bold := func(s string) string {
		if color {
			return "\x1b[1m" + s + "\x1b[0m"
		}
		return s
	}
	mono := func(s string) string {
		if color {
			return "\x1b[36m" + s + "\x1b[0m"
		}
		return s
	}
	dim := func(s string) string {
		if color {
			return "\x1b[38;5;244m" + s + "\x1b[0m"
		}
		return s
	}
	// The dashboard is not running yet — it's a separate command that reads the
	// same history file. Spell that out so the URL isn't mistaken for a live one.
	fmt.Fprintf(out, "\n%s  %s\n", bold("Saved to"), mono(cfg.DBPath))
	fmt.Fprintf(out, "%s  the dashboard is a separate server. Start it, then open the URL it prints:\n", bold("Explore it:"))
	fmt.Fprintf(out, "  %s   %s\n", mono("scout serve"), dim("# reads "+cfg.DBPath+" in this directory; --addr to change the port"))
	fmt.Fprintf(out, "  %s   %s\n", mono("scout scan … --serve"), dim("# scan, then open the dashboard in one step"))
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
	for _, format := range f.export {
		if err := writeExport(cmd, strings.TrimSpace(format), results); err != nil {
			return err
		}
	}
	return nil
}

// exportSlug turns a target into a filesystem-safe filename fragment.
func exportSlug(t core.Target) string {
	s := t.Host()
	if s == "" {
		s = t.Name
	}
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, strings.TrimSpace(s))
	s = strings.Trim(s, "-")
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// writeExport writes a report file (scout-report.<ext>) in the current
// directory, so findings are on disk without opening the dashboard.
func writeExport(cmd *cobra.Command, format string, results []report.Result) error {
	var ext string
	var render func(io.Writer) error
	switch strings.ToLower(format) {
	case "md", "markdown":
		ext, render = "md", func(w io.Writer) error { return report.Markdown(w, results) }
	case "txt", "text":
		ext, render = "txt", func(w io.Writer) error { return report.Text(w, results) }
	case "html":
		ext, render = "html", func(w io.Writer) error {
			return report.HTML(w, results, report.HTMLOptions{Version: scout.Version, Generated: time.Now()})
		}
	case "json":
		ext, render = "json", func(w io.Writer) error { return report.JSON(w, scout.Version, results) }
	default:
		return fmt.Errorf("unknown export format %q (use md, html, txt or json)", format)
	}
	name := "scout-report." + ext
	if len(results) == 1 {
		if slug := exportSlug(results[0].Scan.Target); slug != "" {
			name = "scout-" + slug + "." + ext
		}
	}
	file, err := os.Create(filepath.Clean(name))
	if err != nil {
		return err
	}
	if err := render(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", name)
	return nil
}

func writeSARIF(path string, results []report.Result) error {
	file, err := os.Create(filepath.Clean(path))
	if err != nil {
		return err
	}
	if err := report.SARIF(file, scout.Version, results); err != nil {
		_ = file.Close() // the SARIF error is the one worth returning
		return err
	}
	return file.Close()
}
