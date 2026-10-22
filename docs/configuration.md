# Configuration

Scout layers configuration in this order, each overriding the one before:

1. built-in defaults,
2. `scout.yaml` (in the working directory, or `--config <path>`),
3. `SCOUT_*` environment variables,
4. command-line flags (only when actually passed).

Unknown keys in `scout.yaml` are rejected, so a typo can't silently disable a
setting. Every option is documented with examples in
[`scout.example.yaml`](../scout.example.yaml).

## Sections

- **targets** — what to scan: name, URL and/or repo, environment, per-target
  active opt-in and criticality.
- **scope** — host and path allowlist.
- **criticality** — weight findings by asset (payments API `1.5`, marketing
  site `0.7`); first matching rule wins.
- **rate_limit / concurrency / check_timeout** — scan pacing.
- **db / retention** — SQLite history file and how long scans are kept.
- **window** — a daily scan window (`start`, `end`, `days`, `timezone`).
- **schedules** — cron scans with per-schedule mode caps.
- **alerts** — Slack, Discord, email and HMAC-signed webhooks for new or
  regressed findings.
- **integrations** — optional Pulse and Sentinel URLs.
- **ai** — optional, redacted AI explanations via the Vercel AI Gateway.

## Secrets come from the environment

These are never read from `scout.yaml`:

| Variable | Purpose |
|----------|---------|
| `SCOUT_SIGNING_KEY` | Signs the `X-Scout-Scan` header (share with Sentinel). |
| `SCOUT_JWT_SECRET` | Dashboard session signing key. |
| `SCOUT_USERNAME` / `SCOUT_PASSWORD` | Dashboard login. |
| `SCOUT_SLACK_WEBHOOK` / `SCOUT_DISCORD_WEBHOOK` | Alert webhooks. |
| `SCOUT_SMTP_PASSWORD` | Email alert SMTP password. |
| `SCOUT_PULSE_TOKEN` / `SCOUT_SENTINEL_TOKEN` | Integration auth. |
| `AI_GATEWAY_API_KEY` | Vercel AI Gateway key (required for AI features). |

Other `SCOUT_*` overrides: `SCOUT_ENV`, `SCOUT_MODE`, `SCOUT_TARGETS`,
`SCOUT_DB`, `SCOUT_RATE_LIMIT`, `SCOUT_CONCURRENCY`, `SCOUT_CHECK_TIMEOUT`,
`SCOUT_RETENTION`, `SCOUT_APP_NAME`.

## Dashboard credentials

The defaults (`admin` / `scout`) are refused outside `dev`. Set
`SCOUT_USERNAME` and `SCOUT_PASSWORD` (and a `SCOUT_JWT_SECRET`, or sessions
end on restart) before serving the dashboard in staging or production.
