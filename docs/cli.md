# CLI

```
scout <command> [flags]
```

Global flags: `--config <path>`, `--log-level`, `--log-format`, `--color`.

## scan

Scan a URL and/or a repo and print a report.

```bash
scout scan --target https://example.com --mode safe
scout scan --target http://localhost:8080 --repo . --mode active --env dev
scout scan --target https://example.com --dry-run          # plan only, sends nothing
scout scan --target https://example.com --json  > out.json
scout scan --target https://example.com --sarif out.sarif
```

Key flags: `--target/-t` (repeatable), `--repo`, `--mode/-m`, `--env/-e`,
`--allow-active` (per-target opt-in), `--dry-run`, `--json`, `--sarif`,
`--db`.

## ci

Scan and fail the build on findings. Exit codes: `0` passed, `1` gate failed,
`2` error.

```bash
scout ci --repo . --fail-on high --new-only --sarif out.sarif
```

`--new-only` counts only findings new or regressed since the target's previous
scan (with no history, every finding counts as new).

## serve

Run the dashboard, API, scheduled scans and alerts.

```bash
scout serve --addr :9090 --db scout.db
```

## diff

Show new / fixed / regressed findings between two scans (by ID or unique
prefix, compared oldest → newest).

```bash
scout diff 3f2a9c 9b1c04 --db scout.db
```

## report

Write a printable HTML report (print to PDF). Latest scan of every target by
default, or specific scan IDs.

```bash
scout report --out report.html
scout report 3f2a9c --out shop.html
```

## ownership

Print the token that proves you own a target, required for active scans.

```bash
scout ownership --target https://example.com
```

## prune

Delete scans older than the retention period.

```bash
scout prune --db scout.db --retention 720h
```

## version

```bash
scout version
```
