# Scout

> Point it at your app. See every way in.

[![CI](https://github.com/MUKE-coder/scout/actions/workflows/ci.yml/badge.svg)](https://github.com/MUKE-coder/scout/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/MUKE-coder/scout.svg)](https://pkg.go.dev/github.com/MUKE-coder/scout)
[![Go Report Card](https://goreportcard.com/badge/github.com/MUKE-coder/scout)](https://goreportcard.com/report/github.com/MUKE-coder/scout)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Scout is a self-hosted, open-source **vulnerability scanner and attack-surface
mapper** for developers. You give it a target — a running app, a website, a
repo — and it probes for weaknesses, deduplicates them into a single findings
model, scores the result into a letter grade, and tells you the exact fix for
each issue, ranked by how much safety each fix buys per hour of work.

It is the third tool in a family with **Sentinel** (runtime defense) and
**Pulse** (observability), and shares their ergonomics: one `Mount()`, an
embedded dashboard, and zero external services.

> ## ⚠️ Project status: pre-release (v0.x)
>
> The **engine, scoring, dashboard, CLI, scheduling, alerts, reports,
> integrations and optional AI are complete and tested.** The security
> **checks (collectors)** that actually probe a target are **not yet
> bundled**, so a scan currently runs safely but reports **no findings**.
>
> In other words: the whole product around the checks is ready, and the check
> interface is stable — but Scout cannot find vulnerabilities yet. This is why
> it is tagged `v0.x`, not `v1.0`. Do not rely on it for real security
> coverage until collectors ship. See [CHANGELOG.md](CHANGELOG.md) and
> [`phases.md`](phases.md) for exactly what is and isn't present.

---

## Install

```bash
go install github.com/MUKE-coder/scout/cmd/scout@latest
```

No CGo, no Node needed — the dashboard is embedded in the binary. Builds on
Linux, macOS and Windows.

## Quick start

### Scan a website

```bash
scout scan --target https://example.com --mode safe
```

Safe mode is read-only. Active and intrusive modes against a remote host
require [ownership verification](examples/website-scan/) and are capped by the
environment (`dev` > `staging` > `prod`).

### Add the dashboard to a Gin app

```go
import scout "github.com/MUKE-coder/scout"

scout.Mount(router, scout.Config{AppName: "My API"})
```

That one line adds, under `/scout`:

- the embedded dashboard at `/scout/ui/`,
- the REST API at `/scout/api/`,
- the live WebSocket at `/scout/ws/live`,

and exposes the Gin route table to the scanner so it can flag unprotected
routes before sending any traffic. See [examples/gin-mount](examples/gin-mount/).

### Run the server standalone

```bash
scout serve   # http://localhost:9090/scout/ui/  (dev login: admin / scout)
```

### Fail CI on new findings

```bash
scout ci --repo . --fail-on high --new-only --sarif out.sarif
```

Exit codes: `0` passed, `1` gate failed, `2` error. See
[examples/ci](examples/ci/scout-ci.yml).

## How it works

- **One findings model.** Every collector emits the same `Finding`, with a
  stable fingerprint so Scout tracks new / fixed / regressed across scans.
- **Trustworthy scoring.** A 0–100 score and A–F grade with per-category
  subscores, modeled on SSL Labs: one serious flaw caps the grade. Fixes are
  ranked by points regained per hour of effort.
- **Safe by construction.** Every check declares a mode; every environment
  caps the mode it will run. Scope allowlist, rate limiting, scan windows, a
  kill switch, a signed self-test header and ownership verification are all
  enforced before any active traffic.
- **Self-hosted.** No hosted SaaS, no telemetry. Pure-Go SQLite for storage.

## Configuration

Scout reads `scout.yaml` (or `--config`), overlaid by `SCOUT_*` environment
variables, overlaid by flags. Every option is documented in
[scout.example.yaml](scout.example.yaml): targets, scope, per-asset
criticality, rate limits, scan windows, schedules, alerts (Slack, Discord,
email, signed webhooks), the Pulse/Sentinel integrations, and optional AI.

## Optional AI

With `ai.enabled` and an `AI_GATEWAY_API_KEY`, Scout can explain a finding or
write a stakeholder summary through the [Vercel AI
Gateway](https://vercel.com/docs/ai-gateway) (any provider/model). Findings
are **redacted before anything leaves the process** — evidence bodies are
never sent, and hosts, IPs, emails and tokens are masked — and the dashboard
shows exactly what was sent. Off by default.

## Documentation

- [docs/](docs/) — architecture, safety model, configuration, CLI.
- [CHANGELOG.md](CHANGELOG.md) · [SECURITY.md](SECURITY.md) ·
  [STABILITY.md](STABILITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md)

## Building the dashboard

`ui/dist/` is committed, so consumers never need Node. To rebuild it:

```bash
cd ui/dashboard && npm ci && npm run build
```

## License

[MIT](LICENSE)
