package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/MUKE-coder/scout"
	"github.com/MUKE-coder/scout/core"
)

const labRepo = "https://github.com/MUKE-coder/scout"

func newLabCmd() *cobra.Command {
	var (
		dir  string
		mode string
	)
	cmd := &cobra.Command{
		Use:   "lab",
		Short: "Clone the deliberately-vulnerable lab app and scan its source",
		Long: "Clone Scout's lab (a deliberately-vulnerable app) and run a source scan on it, " +
			"so you can see Scout find real issues in seconds. Prints the steps to also scan it live.",
		Example: "  scout lab\n  scout lab --dir ./scout-lab",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			if _, err := exec.LookPath("git"); err != nil {
				return fmt.Errorf("git is required to fetch the lab: %w", err)
			}

			// Fetch once; reuse an existing lab on re-run. The target dir ends up
			// holding the lab app's files directly (no .git, no rest of the repo).
			if !nonEmptyDir(dir) {
				if err := fetchLab(cmd, dir); err != nil {
					return err
				}
				fmt.Fprintf(out, "Fetched the lab into %s (lab files only).\n", dir)
			} else {
				fmt.Fprintf(out, "Using the existing lab in %s.\n", dir)
			}
			if _, err := os.Stat(filepath.Join(dir, "package.json")); err != nil {
				return fmt.Errorf("%s does not look like the lab (no package.json) — delete it and retry", dir)
			}

			m, err := core.ParseMode(mode)
			if err != nil {
				return err
			}
			cfg, err := scout.NewConfig(scout.WithEnvironment(core.EnvDev), scout.WithMode(m))
			if err != nil {
				return err
			}
			cfg.Targets = []core.Target{{Name: "lab-source", Repo: dir, Environment: core.EnvDev}}
			cfg.DBPath = "scout.db"

			f := scanFlags{mode: mode, env: "dev", db: cfg.DBPath}
			fmt.Fprintf(out, "\nScanning the lab source in %s …\n\n", dir)
			results, err := runScan(cmd, f, cfg)
			if err != nil {
				return err
			}
			if err := writeOutputs(cmd, f, results); err != nil {
				return err
			}
			printDashboardHint(cmd, f, cfg, results)

			// The lab is also a running Next.js app; guide the black-box scan.
			fmt.Fprintf(out, "\nTo also scan it live (needs Node.js):\n")
			fmt.Fprintf(out, "  cd %s && npm install && npm run dev    # http://localhost:4000\n", dir)
			fmt.Fprintf(out, "  scout scan --target http://localhost:4000 --mode active --env dev\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "scout-lab", "directory to put the lab into")
	cmd.Flags().StringVarP(&mode, "mode", "m", "safe", "scan mode for the source scan")
	return cmd
}

func nonEmptyDir(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

// fetchLab fetches only the lab/ folder (partial + sparse clone) and leaves its
// files directly in dir — no .git and none of the rest of the repo.
func fetchLab(cmd *cobra.Command, dir string) error {
	tmp := dir + ".tmp"
	_ = os.RemoveAll(tmp)
	git := func(args ...string) error {
		// #nosec G204 -- fixed git subcommands; paths are local and user-chosen
		c := exec.CommandContext(cmd.Context(), "git", args...)
		c.Stdout, c.Stderr = cmd.ErrOrStderr(), cmd.ErrOrStderr()
		return c.Run()
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Fetching only the lab folder from %s …\n", labRepo)
	if err := git("clone", "--depth", "1", "--filter=blob:none", "--sparse", labRepo, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("git clone failed (needs git 2.25+): %w", err)
	}
	if err := git("-C", tmp, "sparse-checkout", "set", "lab"); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("git sparse-checkout failed: %w", err)
	}
	labSrc := filepath.Join(tmp, "lab")
	if _, err := os.Stat(labSrc); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("lab folder not found in the repo")
	}
	_ = os.RemoveAll(dir)
	if err := os.Rename(labSrc, dir); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("move lab into %s: %w", dir, err)
	}
	return os.RemoveAll(tmp)
}
