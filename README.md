# Scout

> Point it at your app. See every way in.

[![CI](https://github.com/MUKE-coder/scout/actions/workflows/ci.yml/badge.svg)](https://github.com/MUKE-coder/scout/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/MUKE-coder/scout.svg)](https://pkg.go.dev/github.com/MUKE-coder/scout)
[![Go Report Card](https://goreportcard.com/badge/github.com/MUKE-coder/scout)](https://goreportcard.com/report/github.com/MUKE-coder/scout)
[![Release](https://img.shields.io/github/v/release/MUKE-coder/scout?include_prereleases&sort=semver)](https://github.com/MUKE-coder/scout/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Scout is a self-hosted, open-source **vulnerability scanner and attack-surface
mapper** for developers. Point it at a running app, a website, or a repo. It
probes for weaknesses, merges them into one findings model, scores the result
into a letter grade, and tells you the exact fix for each issue — ranked by
how much safety each fix buys per hour of work.

It is the third tool in a family with **Sentinel** (runtime defense) and
**Pulse** (observability), and shares their ergonomics: one `Mount()`, an
embedded dashboard, and zero external services.

> ## ⚠️ Project status: pre-release (v0.x)
>
> The engine, scoring, dashboard, CLI, scheduling, alerts, reports,
> integrations and optional AI are complete and tested. As of **v0.3.0**,
> Scout ships **nine collectors (35 checks)** — headers, TLS, DNS/email,
> exposure, config, a GET-only **crawler** (pages/forms/CSRF/endpoints), a
> **port** scan for exposed services, repo **secret scanning**, and
> **Dockerfile** linting — and finds real, verified issues.
>
> Still to come: **active DAST** input testing (SQLi/XSS/SSRF), **auth/access
> control** (JWT, IDOR, CORS), **Nuclei**, dependency-CVE/SAST/container
> scanning, and a host agent. Until those land Scout covers the HTTP surface,
> exposed services and source analysis — not the full OWASP Top 10 — so it is
> `v0.x`, not `v1.0`. Adding collectors is straightforward: see
> **[Add your own checks](#add-your-own-checks)**.

---

## Contents

- [Install](#install)
- [Concepts in 60 seconds](#concepts-in-60-seconds)
- [Use cases](#use-cases)
  - [1. Scan a public website](#1-scan-a-public-website-black-box)
  - [2. Add the dashboard to a Gin app](#2-add-the-dashboard-to-a-gin-app-white-box)
  - [3. Gate a CI pipeline](#3-gate-a-ci-pipeline)
  - [4. Continuously monitor production](#4-continuously-monitor-production)
  - [5. Track what changed between scans](#5-track-what-changed-between-scans)
  - [6. Produce a report for a client or audit](#6-produce-a-report-for-a-client-or-audit)
  - [7. Wire into Pulse and Sentinel](#7-wire-into-pulse-and-sentinel)
  - [8. Explain findings with AI](#8-explain-findings-with-ai-optional)
- [Safety model](#safety-model)
- [Configuration](#configuration)
- [The dashboard](#the-dashboard)
- [Add your own checks](#add-your-own-checks)
- [Development](#development)
- [Documentation](#documentation)
- [License](#license)

---

## Install

**CLI:**

```bash
go install github.com/MUKE-coder/scout/cmd/scout@latest
scout version
```

No CGo, no Node — the dashboard is baked into the binary. Builds on Linux,
macOS and Windows.

**As a library** (to mount the dashboard in a Gin app):

```bash
go get github.com/MUKE-coder/scout
```

---

## Concepts in 60 seconds

- **Target** — what you scan: a URL (`--target`), a repo (`--repo`), or both.
  Each target has an **environment** (`dev` / `staging` / `prod`).
- **Mode** — how aggressive a scan is: **passive** (read only) → **safe**
  (harmless probes) → **active** (real payloads) → **intrusive** (brute force,
  state-changing). Every check declares its mode.
- **Environment caps the mode.** `prod` runs at most *safe* unless you opt in
  per target; it never runs *intrusive*. This is enforced, not advisory.
- **Finding** — one issue, with severity, confidence, asset, evidence, a
  stack-specific fix, and a stable **fingerprint** so Scout tracks it across
  scans (new / fixed / regressed).
- **Grade** — a 0–100 score and an A–F letter, modeled on SSL Labs: one
  serious flaw caps the grade. Fixes are ranked by points regained per hour.

---

## Use cases

### 1. Scan a public website (black-box)

Nothing is installed on the target. Scout crawls and inspects it from the
outside.

```bash
# Safe, read-only scan (the default).
scout scan --target https://example.com

# Preview what an active scan would do — and send nothing.
scout scan --target https://example.com --mode active --env prod --dry-run

# Machine-readable output.
scout scan --target https://example.com --json  > result.json
scout scan --target https://example.com --sarif result.sarif
```

An **active** scan of a site you own needs proof of ownership first:

```bash
scout ownership --target https://example.com
# publish the printed token as a DNS TXT record or at
# /.well-known/scout-verify.txt, then:
scout scan --target https://example.com --mode active --allow-active
```

Scans are saved to `scout.db` by default, so you can diff and report on them
later. Use `--db ""` to keep nothing.

### 2. Add the dashboard to a Gin app (white-box)

One line mounts Scout inside your app and hands the scanner your real route
table — so it can flag unprotected routes *before* sending any traffic.

```go
package main

import (
    "github.com/gin-gonic/gin"
    scout "github.com/MUKE-coder/scout"
)

func main() {
    r := gin.Default()
    // ... your routes ...
    scout.Mount(r, scout.Config{AppName: "My API"})
    r.Run(":8080")
}
```

Now `/scout/ui/` is the dashboard, `/scout/api/` the REST API, and
`/scout/ws/live` the live scan feed. In `dev` the default login is
`admin` / `scout`; outside dev those defaults are refused (set
`SCOUT_USERNAME` / `SCOUT_PASSWORD`). Full example:
[examples/gin-mount](examples/gin-mount/).

**Route-table checks.** Called after your routes are defined, `Mount`
introspects the Gin engine for its method/path table. To also flag
**unprotected routes before any request is sent**, hand Scout a table that
includes each route's auth middleware — your framework usually knows this
better than Gin's introspection can:

```go
scout.Mount(r, cfg, scout.WithRoutes(
    core.Route{Method: "GET", Path: "/admin", Middleware: []string{"Logger"}},      // flagged: no auth
    core.Route{Method: "GET", Path: "/account", Middleware: []string{"JWTAuth"}},   // ok
))
```

The resolved table is attached to your configured targets and served at
`/scout/api/routes`.

### 3. Gate a CI pipeline

Fail a build when a scan turns up new high/critical issues, and upload results
to GitHub's Security tab.

```bash
scout ci --repo . --fail-on high --new-only --sarif scout.sarif
```

- Exit `0` = passed, `1` = gate failed, `2` = error.
- `--new-only` counts only findings new or regressed since the target's
  previous scan (with no history, every finding counts — it fails safe).

A ready-to-copy workflow is in [examples/ci/scout-ci.yml](examples/ci/scout-ci.yml).

### 4. Continuously monitor production

Run the server; it hosts the dashboard and runs scheduled scans and alerts.

```bash
scout serve --addr :9090 --db scout.db
```

In `scout.yaml`:

```yaml
environment: prod
targets:
  - name: shop
    url: https://shop.example.com

schedules:
  - name: nightly
    cron: "0 3 * * *"      # 3am; mode is capped by the environment (safe in prod)
    targets: [shop]

alerts:
  min_severity: high       # alert only on new/regressed high+ findings
  slack: { webhook_url: "https://hooks.slack.com/services/..." }
```

Scout alerts to **Slack, Discord, email and HMAC-signed webhooks**, only on
findings that are new or regressed since the last scan. The dashboard's
**kill switch** stops all scanning instantly.

### 5. Track what changed between scans

```bash
scout diff 3f2a9c 9b1c04        # by scan ID or unique prefix, oldest → newest
```

Shows new, regressed, fixed and unchanged findings. The same view is on the
dashboard's **History** page. A finding that disappeared and came back counts
as *regressed*, not new.

Mute noise with a reason and an expiry — accepted risks reopen automatically
when they expire (done from the dashboard's finding panel).

### 6. Produce a report for a client or audit

```bash
scout report --out report.html      # open in a browser and print to PDF
```

A self-contained HTML report: grade, category scores, top fixes, and every
open finding with its stack-specific remediation. Text from scanned sites is
escaped, and the API serves it with scripts disabled. Also available from the
dashboard's **Settings → Reports** (download or print-to-PDF), alongside JSON
and CSV export and an **OWASP Top 10 / ASVS compliance** view.

### 7. Wire into Pulse and Sentinel

Optional and auto-detected — Scout is fully useful with neither.

```yaml
integrations:
  pulse:    { url: http://localhost:7070 }   # scans appear as bands on Pulse charts
  sentinel: { url: http://localhost:6060 }   # Scout's exposure score feeds Sentinel
```

Tokens come from `SCOUT_PULSE_TOKEN` / `SCOUT_SENTINEL_TOKEN`. Scout probes
each sibling's health endpoint and stays idle if it is not present.

### 8. Explain findings with AI (optional)

Off unless you enable it and provide a key. Scout talks to the
[Vercel AI Gateway](https://vercel.com/docs/ai-gateway) (any provider/model).

```yaml
ai:
  enabled: true
  model: anthropic/claude-sonnet-5.5
```

```bash
export AI_GATEWAY_API_KEY=vck_...
```

Then the finding panel gains **Explain with AI**, and Settings gains an **AI
stakeholder summary**. Findings are **redacted before anything leaves the
process** — evidence bodies are never sent; hosts, IPs, emails and tokens are
masked — and the dashboard shows exactly what was sent.

---

## Safety model

Scanning is safe by construction, not by good intentions:

- **Mode caps per environment** — enforced; `prod` never runs intrusive.
- **Ownership verification** — active scans of a remote host require a DNS
  `TXT` record or `/.well-known/scout-verify.txt`.
- **One guarded HTTP client** — every request a check makes passes through
  kill switch → scan window → scope allowlist → per-host rate limit, and is
  signed with `X-Scout-Scan` so a WAF can recognize it.
- **Dry-run** — `--dry-run` prints exactly what would run and sends nothing.

Details: [docs/safety.md](docs/safety.md). Only scan systems you own or are
authorized to test.

---

## Configuration

Layered: **defaults → `scout.yaml` → `SCOUT_*` env vars → flags** (a flag wins
only when passed). Unknown keys are rejected, so a typo can't silently disable
a setting. Secrets (signing key, JWT secret, dashboard password, alert and
integration tokens, AI key) come from the environment, never the file.

Every option is documented in [scout.example.yaml](scout.example.yaml); see
[docs/configuration.md](docs/configuration.md) for the precedence rules and
the full `SCOUT_*` list.

---

## The dashboard

Embedded React 19 app (Vercel/Linear aesthetic, dark and light), served at
`/scout/ui/`:

- **Overview** — grade ring, 30-day trend, category subscores, Fix-next,
  per-environment cards.
- **Findings** — filter by severity, category, status and change; bulk accept,
  mute or reopen; a slide-over with evidence, the stack-specific fix, and a
  one-click **Verify fix** that re-runs just that check.
- **Live scan** — per-collector progress over WebSocket, plus the kill switch.
- **History** — compare any two scans.
- **Attack surface** — an interactive domain → host → service → route map,
  colored by worst severity.
- **Compliance** — OWASP Top 10 heatmap and ASVS coverage.
- **Settings** — the effective config, exports, reports and the danger zone.

JWT auth with login rate limiting; default credentials refused outside dev.

---

## Add your own checks

This is the one thing Scout needs to start finding issues, and the extension
point is stable. A check implements `core.Check`, registers itself in
`init()`, makes requests through the guarded client, and attaches a
deterministic remediation — everything else (scoring, dedupe, history, the
dashboard, SARIF, compliance) then works automatically.

See **[docs/collectors.md](docs/collectors.md)** for the full contract and a
complete, compiling example. Contributions of collectors are the most valuable
thing you can send.

---

## Development

```bash
go build ./...
go test ./...
```

Before pushing, run what CI runs (`gofmt -l .`, `go vet ./...`,
`go test -race ./...`, `gosec -exclude-dir=ui ./...`). CI builds with
`CGO_ENABLED=0` on Linux, macOS and Windows. The dashboard build output
`ui/dist/` is committed; rebuild it with `cd ui/dashboard && npm ci && npm run
build`. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Documentation

- [docs/architecture.md](docs/architecture.md) — packages, data flow, the findings model
- [docs/safety.md](docs/safety.md) — modes, caps, ownership, the guard
- [docs/configuration.md](docs/configuration.md) — `scout.yaml`, env vars, precedence
- [docs/cli.md](docs/cli.md) — every command and flag
- [docs/collectors.md](docs/collectors.md) — write a check
- [CHANGELOG.md](CHANGELOG.md) · [SECURITY.md](SECURITY.md) · [STABILITY.md](STABILITY.md)

---

## License

[MIT](LICENSE)
