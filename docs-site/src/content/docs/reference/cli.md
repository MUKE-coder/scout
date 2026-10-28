---
title: CLI reference
description: Every Scout command and flag — scan, ci, serve, diff, report, ownership, prune, version.
---

Scout's root command is `scout`. Run `scout <command> --help` for the authoritative
flag list on your installed version.

```
scout — Point it at your app. See every way in.
```

## Global

| Flag | Meaning |
|---|---|
| `--config <path>` | Path to a config file (otherwise Scout searches for one) |
| `-h, --help` | Help for any command |

## `scout init`

Write a `scout.yaml` in the current directory with every common setting at its
default (and the dashboard login), so settings are easy to change.

```bash
scout init          # writes scout.yaml
scout init --force  # overwrite an existing one
```

## `scout lab`

Clone Scout's deliberately-vulnerable lab app and run a source scan on it — the
fastest way to see Scout find real issues. Prints the steps to also scan it live.

```bash
scout lab                  # clones into ./scout-lab and scans lab/ source
scout lab --dir ./demo     # clone somewhere else
scout lab --mode safe      # scan mode for the source scan
```

## `scout sbom`

Generate a CycloneDX 1.6 SBOM of a repo's dependencies, with each component's
known vulnerabilities (CISA KEV + FIRST EPSS) embedded. See
[Generate an SBOM](/usage/sbom/).

```bash
scout sbom --repo .                 # print to stdout
scout sbom --repo . -o sbom.cdx.json
scout sbom --repo . --no-vulns      # components only (no network)
```

## `scout scan`

Run a scan and print the report.

| Flag | Default | Meaning |
|---|---|---|
| `-t, --target <url>` | — | Target URL (repeatable) |
| `--repo <path>` | — | Local repo path for code & supply-chain checks |
| `-m, --mode <mode>` | `safe` | `passive` \| `safe` \| `active` \| `intrusive` |
| `-e, --env <env>` | `dev` | `dev` \| `staging` \| `prod` (caps the mode) |
| `--db <file>` | `scout.db` | SQLite history file (`""` keeps nothing) |
| `--allow-active` | `false` | Per-target opt-in: active in prod, intrusive in staging |
| `--dry-run` | `false` | Print what would run, run nothing |
| `--json` | `false` | Print JSON instead of the report |
| `--sarif <file>` | — | Also write SARIF 2.1.0 to this file |
| `--export <formats>` | — | Also write `scout-report.<ext>` here: any of `md,html,txt,json` |
| `--check-timeout <dur>` | `60s` | Max time per check (e.g. `120s`); raise it for slow targets |
| `--templates <dir>` | — | Directory of extra YAML [detection templates](/usage/templates/) (also `SCOUT_TEMPLATES`) |
| `--sbom <file>` | — | Also write a CycloneDX SBOM (with KEV/EPSS) of `--repo` to this file |
| `--serve` | `false` | After the scan, open the dashboard (runs until Ctrl+C) |
| `--serve-addr <addr>` | `:9090` | Address for the `--serve` dashboard |

```bash
scout scan --target http://localhost:3000 --mode active --env dev
scout scan --repo . --sarif scout.sarif
```

## `scout ci`

Scan and exit non-zero on findings — for pull-request gating. Takes all `scan`
flags, plus:

| Flag | Default | Meaning |
|---|---|---|
| `--fail-on <severity>` | `high` | Fail when a finding is at or above this severity |
| `--new-only` | `false` | Only count findings new or regressed since the last scan |

```bash
scout ci --repo . --fail-on high --new-only
```

## `scout serve`

Run the dashboard and any scheduled scans.

```bash
scout serve
```

Dashboard credentials come from the [config](/reference/configuration/); defaults
are refused outside `dev`.

## `scout diff`

Compare two saved scans.

```bash
scout diff <scan-a> <scan-b>
```

## `scout report`

List recent scans, or re-print one.

```bash
scout report              # list
scout report <scan-id>    # re-print
```

## `scout ownership`

Print the token that proves you own a target (required for active scans of a
non-local host).

| Flag | Meaning |
|---|---|
| `-t, --target <url>` | Target URL (required) |

```bash
scout ownership --target https://example.com
```

## `scout prune`

Delete scans older than the retention period.

```bash
scout prune
```

## `scout version`

```bash
scout version
```
