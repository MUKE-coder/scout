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
				return fmt.Errorf("git is required to clone the lab: %w", err)
			}

			// Clone once; reuse an existing checkout on re-run.
			if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
				fmt.Fprintf(out, "Cloning the lab into %s …\n", dir)
				// #nosec G204 -- fixed git subcommand and repo; dir is a local path the user chose
				clone := exec.CommandContext(cmd.Context(), "git", "clone", "--depth", "1", labRepo, dir)
				clone.Stdout, clone.Stderr = cmd.ErrOrStderr(), cmd.ErrOrStderr()
				if err := clone.Run(); err != nil {
					return fmt.Errorf("git clone failed: %w", err)
				}
			} else {
				fmt.Fprintf(out, "Using the existing clone in %s.\n", dir)
			}

			labDir := filepath.Join(dir, "lab")
			if _, err := os.Stat(labDir); err != nil {
				return fmt.Errorf("lab directory not found at %s", labDir)
			}

			m, err := core.ParseMode(mode)
			if err != nil {
				return err
			}
			cfg, err := scout.NewConfig(scout.WithEnvironment(core.EnvDev), scout.WithMode(m))
			if err != nil {
				return err
			}
			cfg.Targets = []core.Target{{Name: "lab (source)", Repo: labDir, Environment: core.EnvDev}}
			cfg.DBPath = "scout.db"

			f := scanFlags{mode: mode, env: "dev", db: cfg.DBPath}
			fmt.Fprintf(out, "\nScanning the lab source (%s) …\n\n", labDir)
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
			fmt.Fprintf(out, "  cd %s && npm install && npm run dev    # http://localhost:4000\n", labDir)
			fmt.Fprintf(out, "  scout scan --target http://localhost:4000 --mode active --env dev\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "scout-lab", "directory to clone the lab into")
	cmd.Flags().StringVarP(&mode, "mode", "m", "safe", "scan mode for the source scan")
	return cmd
}
