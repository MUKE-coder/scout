---
title: Scan flags, explained
description: Every flag on a scout scan command — what it does and, for the modes, exactly what Scout checks — walked through token by token.
---

Take a full command and read it left to right:

```bash
scout scan --target https://example.com --mode active --env prod --allow-active
```

| Token | Meaning |
|---|---|
| `scout scan` | Run a scan and print a graded report. |
| `--target https://example.com` | The running app to scan (black-box). Repeatable. |
| `--mode active` | **How aggressive** the scan is — see the table below. |
| `--env prod` | **Where** the target lives; this **caps** the mode. |
| `--allow-active` | Per-target opt-in that lets `active` run in `prod` (and `intrusive` in `staging`). |

## What each `--mode` checks

The mode decides which checks run. Each level **includes the ones below it**.

| Mode | What it adds | Example checks |
|---|---|---|
| `passive` | Reads only what the app already returns — no extra requests beyond a crawl. | Security headers, cookie flags, version/server banners, JWT inspection |
| `safe` | Adds benign, non-mutating requests. **The default.** | Exposed `.env`/`.git`/backups, CORS, GraphQL introspection, directory listing, mixed content, missing SRI, stack-trace disclosure, DNS/email (SPF/DMARC/DKIM) |
| `active` | Sends crafted (but non-destructive) inputs to **confirm** a weakness. | SQL injection, OS command injection, open redirect, reflected XSS, SSRF, path traversal, IDOR (with test identities) |
| `intrusive` | The most thorough active testing. | The deepest probes |

Scout **ships no destructive payloads** — "active" means it injects a benign
marker and checks the response, never deletes data or runs attacker code.

Run `scout scan --dry-run` to print exactly which checks a given mode/env would
run (and which it would skip, and why) without sending anything.

## How `--env` caps `--mode`

The environment is a safety ceiling:

| `--env` | Highest mode by default | Raise it with |
|---|---|---|
| `dev` | `intrusive` | — |
| `staging` | `active` | `--allow-active` → intrusive |
| `prod` | `safe` | `--allow-active` → active |

So in the example, `--mode active --env prod` would normally be **capped to
safe** — `--allow-active` is what lets it actually run active. For a **non-local**
target, active mode *also* needs [ownership verification](/start/ownership/).

## Every other flag

| Flag | Default | What it does |
|---|---|---|
| `--repo <path>` | — | Scan a local repo for secrets, Dockerfiles, weak crypto and reachable CVEs |
| `--check-timeout <dur>` | `60s` | Max time per check; raise for slow targets |
| `--serve` | off | After the scan, open the dashboard on the same results |
| `--serve-addr <addr>` | `:9090` | Address for the `--serve` dashboard |
| `--export <formats>` | — | Write `scout-<target>.<ext>` here: `md,html,txt,json` |
| `--sarif <file>` | — | Also write SARIF 2.1.0 (for GitHub code scanning) |
| `--json` | off | Print JSON instead of the report |
| `--db <file>` | `scout.db` | History file (`""` keeps nothing) |
| `--dry-run` | off | Print the plan, run nothing |
| `--allow-active` | off | Per-target opt-in for active/intrusive beyond the env cap |

See also [Modes & environments](/start/modes/), [Ownership verification](/start/ownership/)
and the [CLI reference](/reference/cli/).
