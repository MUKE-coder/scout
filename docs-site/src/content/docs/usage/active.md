---
title: Active scanning
description: Run the injection and auth probes safely — on localhost with no setup, or on a public host you own with ownership verification.
---

Active mode is where Scout sends crafted inputs to **confirm** a weakness rather
than just observe one. It is non-destructive — Scout injects a benign marker and
checks the response — but because it is still aggressive testing, it is gated.

## The gate, in short

1. The [environment caps the mode](/start/modes/). `prod` caps at safe; raise it per
   target with `--allow-active`.
2. A **non-local** target additionally needs [ownership verification](/start/ownership/).
3. Localhost and private IPs are exempt from the ownership requirement.

## On localhost (no setup)

```bash
scout scan --target http://localhost:3000 --mode active --env dev
```

That is all it takes locally. This runs the active probes:

| Check | Class |
|---|---|
| `app.sqli` | SQL injection |
| `app.cmd-injection` | OS command injection |
| `app.ssrf` | Server-side request forgery (reflected) |
| `app.path-traversal` | Path traversal |
| `app.open-redirect` | Open redirect |
| `app.reflected-xss` | Reflected XSS |
| `auth.idor` | Broken object-level authorization — needs [test identities](/usage/idor/) |

:::note
Scout also registers scaffolds for `app.ssti`, `app.xxe`, `app.file-upload`,
`app.business-logic` and `auth.mass-assignment`. These appear in the catalog and
run in active scans but report nothing until their probe logic is implemented —
they ship no attack payloads.
:::

## On a host you own

Prove ownership first (see [Ownership verification](/start/ownership/)), then:

```bash
scout ownership --target https://staging.example.com   # publish the token it prints
scout scan --target https://staging.example.com --mode active --env staging --allow-active
```

## Dry-run it first

Always safe to preview exactly what active mode will do:

```bash
scout scan --target https://staging.example.com --mode active --env staging --allow-active --dry-run
```
