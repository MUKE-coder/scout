package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// defaultConfigYAML is a fully-annotated scout.yaml with every common setting at
// its default, so a new user can open it and change what they need.
const defaultConfigYAML = `# Scout configuration. Everything here is optional — Scout runs with sensible
# defaults — but having the file makes settings easy to change.
# Docs: https://scout.codetotech.com/reference/configuration/

app_name: Scout
environment: dev          # dev | staging | prod  (caps the maximum mode)
mode: safe                # passive | safe | active | intrusive

# What to scan. Add your own; 'url' is a running app, 'repo' is a local path.
targets:
  - name: local
    url: http://localhost:3000
    environment: dev
  # - name: this-repo
  #   repo: .

# Disposable test accounts for the IDOR check (never real users).
# identities:
#   - name: alice
#     headers: { Cookie: "session=alice-token" }
#     owns: ["/api/users/1"]
#   - name: bob
#     headers: { Cookie: "session=bob-token" }
#     owns: ["/api/users/2"]

# Dashboard login. The defaults (admin / scout) are allowed in dev only; set
# your own before serving outside dev.
username: admin
password: scout
jwt_secret: ""            # a long random string; generated if empty (sessions reset on restart)

# Signs ownership tokens and the X-Scout-Scan header. Keep it stable.
signing_key: ""

# Operational tuning.
rate_limit: 10            # max outbound requests/sec per target
concurrency: 4            # checks run in parallel
check_timeout: 60s        # max time per check (raise for slow targets)
db: scout.db              # SQLite history file ("" keeps nothing)
retention: 2160h          # keep 90 days of history

# Run scans automatically while 'scout serve' is up.
# schedules:
#   - name: nightly
#     target: local
#     cron: "0 2 * * *"

# Restrict when scans may run.
# window:
#   days: [Mon, Tue, Wed, Thu, Fri]
#   start: "18:00"
#   end: "06:00"
`

func newInitCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a scout.yaml with all defaults (easy to edit)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			const name = "scout.yaml"
			if _, err := os.Stat(name); err == nil && !force {
				return fmt.Errorf("%s already exists (use --force to overwrite)", name)
			}
			if err := os.WriteFile(filepath.Clean(name), []byte(defaultConfigYAML), 0o600); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s — open it to change settings, then run `scout scan` or `scout serve`.\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing scout.yaml")
	return cmd
}
