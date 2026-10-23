---
title: IDOR & test identities
description: Detect broken object-level authorization by giving Scout two disposable test accounts to compare what each may reach.
---

**IDOR** (Insecure Direct Object Reference / broken object-level authorization)
is proven by comparison: one identity owns a private object; a *different*
identity must not be able to read it. Scout's `auth.idor` check needs two
disposable test accounts to make that comparison.

:::caution
Use **throwaway test accounts only** — never real users. Scout's probe is
read-only (GET), compares response bodies by hash, and never stores their
contents, but it is still sending authenticated requests.
:::

## How it works

For each identity's owned resource, Scout:

1. Confirms the **owner** can actually read it (establishes the baseline).
2. Re-requests it as **every other identity**.
3. Flags a **confirmed** IDOR (High) when another identity receives the
   byte-identical object.

## Configure the identities

Each identity carries the headers that authenticate it and the resources it
legitimately owns. In your [config file](/reference/configuration/):

```yaml
identities:
  - name: alice
    headers:
      Cookie: "session=alice-token"
    owns:
      - /api/users/1
  - name: bob
    headers:
      Cookie: "session=bob-token"
    owns:
      - /api/users/2
```

Or programmatically when you [embed Scout](/usage/library/):

```go
scout.WithTestIdentities(
    core.Identity{
        Name:    "alice",
        Headers: map[string]string{"Cookie": "session=alice-token"},
        Owns:    []string{"/api/users/1"},
    },
    core.Identity{
        Name:    "bob",
        Headers: map[string]string{"Cookie": "session=bob-token"},
        Owns:    []string{"/api/users/2"},
    },
)
```

`owns` entries may be absolute URLs or paths resolved against the target.

## Run it

IDOR is an active check:

```bash
scout scan --target http://localhost:3000 --mode active --env dev
```

With fewer than two identities configured, `auth.idor` reports nothing — it is
*unconfigured*, not a silent pass.

## Try it on the lab

The lab app exposes an IDOR at `/api/users/[id]`. See
[IDOR on the lab](/lab/idor/) for a worked example.
