package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	scout "github.com/MUKE-coder/scout"
	"github.com/MUKE-coder/scout/selfupdate"
)

func newUpdateCmd() *cobra.Command {
	var checkOnly bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update scout to the latest released version",
		Long: "Check GitHub for the latest Scout release and, unless --check is given, replace this " +
			"binary with it. Scout also checks for updates automatically (at most once a day) and " +
			"self-updates on your next run; set SCOUT_NO_UPDATE=1 to turn that off.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			rel, err := selfupdate.Latest(ctx)
			if err != nil {
				return fmt.Errorf("checking for updates: %w", err)
			}
			if !selfupdate.Newer(scout.Version, rel.Tag) {
				fmt.Fprintf(out, "Scout %s is already the latest version.\n", scout.Version)
				return nil
			}
			if checkOnly {
				fmt.Fprintf(out, "Scout %s is available (you have %s). Run `scout update` to upgrade.\n", rel.Tag, scout.Version)
				return nil
			}
			fmt.Fprintf(out, "Updating Scout %s → %s …\n", scout.Version, rel.Tag)
			if err := selfupdate.Apply(ctx, rel); err != nil {
				return fmt.Errorf("applying update: %w", err)
			}
			rememberCheck(rel.Tag)
			fmt.Fprintf(out, "Updated to %s.\n", rel.Tag)
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false, "only report whether an update is available; do not install")
	return cmd
}

// --- auto-update on startup -------------------------------------------------

// updateState throttles the automatic check so it hits the network at most once
// a day.
type updateState struct {
	LastCheck time.Time `json:"last_check"`
	Latest    string    `json:"latest"`
}

const checkInterval = 24 * time.Hour

// maybeAutoUpdate runs before every command (except the ones that opt out). At
// most once a day it asks GitHub for the latest release; if a newer version is
// out, it self-updates and relaunches the original command on the new binary. It
// never blocks or fails the user's command — any problem is reported and skipped.
func maybeAutoUpdate(cmd *cobra.Command) {
	if !autoUpdateEnabled(cmd) {
		return
	}
	st := readCheckState()
	if time.Since(st.LastCheck) < checkInterval && !selfupdate.Newer(scout.Version, st.Latest) {
		return // checked recently, nothing newer was seen
	}

	// Capture the executable path now, before Apply renames anything (on Windows
	// the running .exe is moved aside), so we relaunch the new binary in place.
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, lerr := filepath.EvalSymlinks(exe); lerr == nil {
		exe = resolved
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
	defer cancel()
	rel, err := selfupdate.Latest(ctx)
	if err != nil {
		return // offline or rate-limited: don't bother the user
	}
	rememberCheck(rel.Tag)
	if !selfupdate.Newer(scout.Version, rel.Tag) {
		return
	}

	w := cmd.ErrOrStderr()
	fmt.Fprintf(w, "Scout %s is available (you have %s). Updating…\n", rel.Tag, scout.Version)
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer applyCancel()
	if err := selfupdate.Apply(applyCtx, rel); err != nil {
		fmt.Fprintf(w, "auto-update failed: %v — continuing with the current version.\n", err)
		return
	}
	fmt.Fprintf(w, "Updated to %s. Relaunching…\n\n", rel.Tag)
	relaunch(exe)
}

// autoUpdateEnabled decides whether the automatic check should run for this
// invocation.
func autoUpdateEnabled(cmd *cobra.Command) bool {
	if os.Getenv("SCOUT_NO_UPDATE") != "" || os.Getenv("SCOUT_UPDATED") != "" || os.Getenv("CI") != "" {
		return false
	}
	// Never self-update a dev build (no real version to compare).
	if strings.Contains(scout.Version, "dev") {
		return false
	}
	switch cmd.Name() {
	// Skip commands where a surprise relaunch is wrong: the updater itself, a
	// version query, the long-running server, and CI (reproducibility).
	case "update", "version", "serve", "ci", "scout", "help":
		return false
	}
	return true
}

// relaunch runs the original command with the freshly-installed binary and exits
// with its status. SCOUT_UPDATED=1 stops the child from checking again.
func relaunch(exe string) {
	c := exec.Command(exe, os.Args[1:]...) // #nosec G204 G702 -- re-running ourselves (os.Executable path) with our own args
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Env = append(os.Environ(), "SCOUT_UPDATED=1")
	err := c.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		os.Exit(ee.ExitCode())
	}
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// --- throttle state ---------------------------------------------------------

func checkStatePath() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "scout")
	_ = os.MkdirAll(dir, 0o750)
	return filepath.Join(dir, "update-check.json")
}

func readCheckState() updateState {
	var st updateState
	b, err := os.ReadFile(checkStatePath()) // #nosec G304 -- fixed cache path
	if err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func rememberCheck(latest string) {
	b, _ := json.Marshal(updateState{LastCheck: time.Now(), Latest: latest})
	_ = os.WriteFile(checkStatePath(), b, 0o600)
}
