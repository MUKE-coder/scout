---
title: Configuration
description: The Scout config file — targets, mode, identities, schedules, dashboard credentials, retention and integrations — with a full annotated example.
---

Scout works with zero config from the CLI. For repeatable scans, scheduled runs,
the dashboard and [test identities](/usage/idor/), use a config file. Scout
searches for one, or pass `--config <path>`.

## Minimal

```yaml
app_name: My App
environment: dev
mode: safe
targets:
  - name: local
    url: http://localhost:3000
    environment: dev
```

## Full example

```yaml
app_name: My App
environment: staging          # dev | staging | prod — caps the mode
mode: safe                    # passive | safe | active | intrusive

targets:
  - name: staging
    url: https://staging.example.com
    environment: staging
    allow_active: false       # per-target opt-in for active/intrusive
    criticality: 1.0          # weights findings on this target
  - name: repo
    repo: .                   # source & supply-chain checks

# Disposable test accounts for access-control checks (IDOR). Never real users.
identities:
  - name: alice
    headers:
      Cookie: "session=alice-token"
    owns:
      - /api/users/1
  - name: bob
    headers:
      Cookie: "session=bob-token"
    owns:
      - /api/users/2

# Run scans automatically while `scout serve` is up.
schedules:
  - name: nightly
    target: staging
    cron: "0 2 * * *"

# Restrict when scans may run.
window:
  days: [Mon, Tue, Wed, Thu, Fri]
  start: "18:00"
  end: "06:00"

# Dashboard login (defaults are refused outside dev).
username: admin
password: "a-strong-password"
jwt_secret: "a-long-random-string"

# Signs ownership tokens and the X-Scout-Scan self-test header. Keep it stable.
signing_key: "another-long-random-string"

# Operational tuning.
rate_limit: 10                # max outbound requests/sec per target
concurrency: 4                # checks run in parallel
check_timeout: 60s            # per-check bound
db: scout.db                  # SQLite history ("" keeps nothing)
retention: 2160h              # keep 90 days of history

# Weight findings by asset. First matching rule wins.
criticality:
  - match: "/api/billing"
    weight: 1.5

# Notify on new or regressed findings after each saved scan.
alerts:
  # … webhook / email settings …

# Optional integrations.
integrations:
  # pulse / sentinel settings …
```

## Key fields

| Field | Meaning |
|---|---|
| `environment` | Caps the maximum mode (see [Modes](/start/modes/)) |
| `mode` | Requested mode; always capped by environment |
| `targets[]` | What to scan — `url` (black-box) and/or `repo` (source) |
| `identities[]` | Test accounts for `auth.idor` — headers + owned resources |
| `schedules[]` | Cron scans that run under `scout serve` |
| `window` | When scans are allowed to run |
| `username` / `password` / `jwt_secret` | Dashboard auth (required outside dev) |
| `signing_key` | Signs ownership tokens — keep it stable |
| `rate_limit` / `concurrency` / `check_timeout` | Politeness & performance |
| `db` / `retention` | History storage and how long it is kept |
| `criticality[]` | Weight findings by asset path |

## CLI overrides

Flags override the file for a single run — `--target`, `--mode`, `--env`, `--db`,
`--allow-active`, and so on. See the [CLI reference](/reference/cli/).
