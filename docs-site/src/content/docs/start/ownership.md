---
title: Ownership verification
description: Active scans of a public host require proof you own it. How to generate the ownership token and publish it via DNS or a well-known file.
---

Active scanning sends crafted inputs to a target. Doing that to a host you do not
control is unauthorized testing. So for any **non-local** target, Scout requires
proof of ownership before it will run active checks.

:::note
**Localhost and private IPs are exempt.** Scanning `http://localhost:3000` or a
`10.x`/`192.168.x` address in active mode needs no token — Scout treats those as
yours.
:::

## 1. Generate the token

```bash
scout ownership --target https://example.com
```

Scout prints a token derived from your config's signing key and the host, plus
exactly where to publish it:

```
Ownership token for example.com:

  scout-verify-abc123...

Publish it in one of these places before running an active scan:
  DNS TXT on _scout-verify.example.com   scout-verify=scout-verify-abc123...
  DNS TXT on example.com                 scout-verify=scout-verify-abc123...
  File   https://example.com/.well-known/scout-verify   containing the token
```

:::caution
The token is tied to your **signing key** (in your [config](/reference/configuration/)).
Generate and verify with the same config, or the token will not match. If you
have no key set, Scout generates one — keep it stable so tokens stay valid.
:::

## 2. Publish it

Pick one:

- **DNS TXT** — add a `TXT` record on `_scout-verify.example.com` (or the apex)
  with the `scout-verify=...` value. Best for a domain you administer.
- **Well-known file** — serve the token at
  `https://example.com/.well-known/scout-verify`. Best when you can deploy a file
  but not change DNS.

## 3. Run the active scan

```bash
scout scan --target https://example.com --mode active --env prod --allow-active
```

Scout re-checks the token at scan time. If it is present and matches, the active
checks run; if not, Scout refuses and tells you what it expected.

## Why both a token and `--allow-active`?

They guard different things. `--allow-active` is **your** intent ("yes, be
aggressive here"); the token proves **authorization** ("yes, this host is mine").
Active scanning of a public target needs both. See [Modes & environments](/start/modes/).
