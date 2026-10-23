---
title: Modes & environments
description: Scout's four scan modes, the three environments that cap them, and how the two combine to keep scans safe by default.
---

Scout separates **how aggressive** a scan is (the mode) from **where** it runs
(the environment). The environment caps the mode, so you cannot accidentally run
an intrusive scan against production.

## The four modes

| Mode | What it does | Example checks |
|---|---|---|
| `passive` | Reads only what the app already gives you. No extra requests beyond a crawl. | Response headers, cookie flags, version banners |
| `safe` | Adds benign, non-mutating requests. The default. | Exposed `.env`/`.git`, CORS, GraphQL introspection, directory listings |
| `active` | Sends crafted (but non-destructive) inputs to confirm a weakness. | SQL injection, command injection, open redirect, reflected XSS, IDOR |
| `intrusive` | The most thorough active testing. | Reserved for the deepest probes |

Scout **never ships destructive payloads**. "Active" means it injects a benign
marker and checks the response — it does not delete data or run attacker code.

## The three environments

The `--env` flag names where the target lives, and that **caps** the maximum
mode:

| Environment | Max mode (default) | Raise it with |
|---|---|---|
| `dev` | `intrusive` | — |
| `staging` | `active` | `--allow-active` → intrusive |
| `prod` | `safe` | `--allow-active` → active |

So:

```bash
# dev: anything goes
scout scan --target http://localhost:3000 --mode active --env dev

# prod: capped at safe unless you opt in per target
scout scan --target https://example.com --mode active --env prod            # runs SAFE (capped)
scout scan --target https://example.com --mode active --env prod --allow-active  # runs ACTIVE
```

## Why active needs more than a flag

Running active checks against a host you do not control is intrusive testing of
someone else's system. For any **non-local** target, active mode also requires
[ownership verification](/start/ownership/) — a token you publish on the host —
on top of `--allow-active`. Localhost and private IPs are exempt.

## See what will run first

```bash
scout scan --target https://example.com --mode active --env prod --dry-run
```

`--dry-run` prints every check Scout would run (and every one it would skip, and
why) without sending a single probe.
