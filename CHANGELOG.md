# Changelog

All notable changes to Scout are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Scout follows
[Semantic Versioning](https://semver.org/). While the major version is `0`,
the public API may change between minor versions.

## [Unreleased]

### Not yet included
- **Security checks / collectors.** The collectors that probe a target (TLS,
  headers, exposed files, ports, DNS/email, Nuclei templates, DAST, auth,
  host and code/supply-chain checks) are not bundled yet. The scan engine,
  check interface and scoring are complete and tested, so scans run safely
  but report no findings until collectors ship.
- **WAF effectiveness test** (Sentinel) — needs the offensive check corpus.
- **AI draft-fix-PR** — needs repository and GitHub write access.

## [0.1.0] — 2026-10-22

First tagged release. Everything around the security checks is in place.

### Added
- **Core model** — unified `Finding`, `Asset`, `Evidence`, `Remediation`;
  `Mode`, `Category`, `Severity`, `Confidence`, `Status`; stable fingerprints
  for new/fixed/regressed tracking.
- **Engine** — worker-pool scan loop with per-check timeouts and panic
  recovery, mode enforcement (environment caps), scope allowlist, per-host
  rate limiting, scan windows, a global kill switch, dry-run/plan mode, a
  signed `X-Scout-Scan` self-test header, and target ownership verification
  (DNS TXT or `/.well-known/scout-verify.txt`) before active mode.
- **Findings pipeline** — fingerprint dedupe, first/last-seen and status
  carry-over, persistence and a non-blocking event bus.
- **Scoring** — exponential-decay per-category scores, weighted overall,
  SSL-Labs-style hard grade caps, configurable per-asset criticality, and a
  "fix next" ranking by points regained per effort hour; golden-file tests.
- **Storage** — in-memory ring buffer and pure-Go SQLite (no CGo), with
  retention pruning.
- **CLI** — `scan`, `serve`, `ci`, `diff`, `ownership`, `prune`, `report`,
  `version`; pretty, JSON and SARIF 2.1.0 output; `scout.yaml` + `SCOUT_*`
  env + flags.
- **Dashboard** — embedded React 19 / Vite / Tailwind 4 app (committed
  `ui/dist`, `//go:embed`): overview, findings with filters and bulk actions,
  finding detail with evidence and verify-fix, live scan over WebSocket,
  history/diff, attack-surface map, OWASP/ASVS compliance view and settings.
  JWT auth with login rate limiting; default credentials refused outside dev.
- **Operations** — cron schedules with per-schedule mode caps; alerts to
  Slack, Discord, email and HMAC-signed webhooks; accepted-risk workflow with
  reason and expiry.
- **Reports** — self-contained printable HTML report (print to PDF), from the
  API and `scout report`.
- **Integrations** — optional, auto-detected Pulse overlay
  (`/pulse/api/test-runs`) and shared security score with Sentinel.
- **Optional AI** — redacted explanations and stakeholder summaries via the
  Vercel AI Gateway, off by default.

[Unreleased]: https://github.com/MUKE-coder/scout/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MUKE-coder/scout/releases/tag/v0.1.0
