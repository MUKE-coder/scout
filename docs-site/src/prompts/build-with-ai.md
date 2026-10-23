You are helping me use **Scout**, a self-hosted vulnerability scanner and
attack-surface mapper for developers (Go, single binary, no account).
Repository: https://github.com/MUKE-coder/scout — docs: https://scout-docs.codetotech.com

# What Scout is

Point Scout at a running app (black-box) or a code repository (source /
supply-chain). It runs a set of "checks" (collectors), produces findings with a
severity, confidence, CWE/OWASP mapping and remediation, then scores the target
with a letter grade. It can print a terminal report, JSON, or SARIF 2.1.0.

# Install

```bash
go install github.com/MUKE-coder/scout/cmd/scout@latest
# or run without installing:
go run github.com/MUKE-coder/scout/cmd/scout@latest scan --target http://localhost:3000
```

# The commands

- `scout scan`   — run a scan. Key flags:
  - `--target, -t <url>`  target URL (repeatable)
  - `--repo <path>`       local repo path for code & supply-chain checks
  - `--mode, -m <mode>`   passive | safe | active | intrusive (default safe)
  - `--env, -e <env>`     dev | staging | prod (caps the mode)
  - `--allow-active`      per-target opt-in for active in prod / intrusive in staging
  - `--json`              print JSON instead of the report
  - `--sarif <file>`      also write SARIF 2.1.0
  - `--db <file>`         SQLite history file ("" keeps nothing)
  - `--dry-run`           print what would run, run nothing
- `scout ci`     — scan and exit non-zero on findings. `--fail-on <severity>` (default high), `--new-only`.
- `scout serve`  — dashboard + scheduled scans.
- `scout diff <a> <b>` — compare two saved scans.
- `scout report [id...]` — re-print a report from history.
- `scout ownership --target <url>` — print the token that proves you own a host.
- `scout prune` / `scout version`.

# Rules that matter

1. **Modes are capped by environment.** `dev` allows up to intrusive; `prod`
   caps at safe unless the target opts in with `--allow-active`.
2. **Active scans of a non-local host need ownership proof.** Run
   `scout ownership --target https://example.com`, publish the token as a DNS
   TXT record or at `/.well-known/`, then scan with `--mode active`.
   Localhost / private IPs need no proof.
3. **Source scanning uses `--repo`.** Secrets, Dockerfile issues, weak crypto,
   dangerous sinks and reachable Go CVEs (via govulncheck) are repo checks.
4. **Scout ships no destructive payloads.** Active checks are non-destructive.

# When I ask you to use Scout

- To scan a local dev app: `scout scan --target http://localhost:<port> --mode active --env dev`.
- To scan this repo for secrets/CVEs: `scout scan --repo . --mode safe`.
- To gate CI: add `scout ci --repo . --fail-on high` (and/or a `--target`) as a step.
- Prefer `--new-only` in CI once a baseline scan exists, so only new/regressed
  findings fail the build.
- Read findings from `--json` when you need to act on them programmatically;
  emit `--sarif` to upload into GitHub code scanning.

Ask me for the target URL, the environment, and whether the host is one I own
before running an active scan against anything that is not localhost.
