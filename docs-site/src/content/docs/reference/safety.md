---
title: Safety model
description: How Scout stays safe — mode caps, ownership verification, non-destructive probes, rate limits, scope, scan windows and the self-test header.
---

Scout is built to be run by developers against their own systems, including in
CI. Several layers keep it from doing damage or testing something you do not own.

## 1. Modes are capped by environment

The `--env` you name caps the maximum mode. `prod` tops out at **safe**; raising
it to active needs an explicit per-target `--allow-active`. You cannot
accidentally run an intrusive scan against production. See
[Modes & environments](/start/modes/).

## 2. Active scans require ownership proof

For any **non-local** target, active mode also requires a published
[ownership token](/start/ownership/) — a DNS TXT record or a well-known file that
proves the host is yours. Localhost and private IPs are exempt. This is what stops
Scout from being pointed at a stranger's site in aggressive mode.

## 3. Probes are non-destructive

Scout ships **no destructive or exploit payloads**. Active checks inject a benign
marker and read the response to confirm a weakness; they do not delete data, run
attacker code, or complete real transactions. The remaining offensive classes
(SSTI, XXE, upload, business-logic, mass-assignment) are **scaffolds** — registered
but inert until their logic is written.

## 4. Rate limits and concurrency

Outbound requests are capped per target (`rate_limit`, default 10/sec) and checks
run with bounded concurrency, so a scan stays polite and will not overwhelm the
target.

## 5. Scope

Scout never widens scope implicitly. A scan touches the target's own host unless
you explicitly add hosts to the scope allowlist.

## 6. Scan windows

A `window` in the [config](/reference/configuration/) restricts when scans may run,
so a scheduled or triggered scan never fires outside an allowed time.

## 7. The self-test header

Every request Scout makes carries a signed `X-Scout-Scan` header, so your own app
and logs can recognize scan traffic and distinguish it from a real attacker.

## 8. Self-hosted, nothing leaves your machine

Scout is a single binary. Scan history lives in a local SQLite file; the dashboard
is embedded. There is no account, no telemetry, and no third-party service in the
loop.

## Preview before you run

```bash
scout scan --target https://example.com --mode active --env prod --allow-active --dry-run
```

`--dry-run` prints every check that would run, and every one it would skip and
why, without sending a single request.
