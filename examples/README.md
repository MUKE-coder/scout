# Examples

- **[gin-mount/](gin-mount/)** — a minimal Gin app that mounts Scout with one
  line (`scout.Mount`). Run it and open the embedded dashboard. Builds as part
  of the module, so it always compiles against the current API.
- **[website-scan/](website-scan/)** — scanning an arbitrary website from the
  CLI, including dry-run, ownership verification and SARIF output.
- **[ci/scout-ci.yml](ci/scout-ci.yml)** — a GitHub Actions workflow that runs
  `scout ci` and uploads SARIF to the Security tab.
