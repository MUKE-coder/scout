---
title: Out-of-band testing (OAST)
description: Scout confirms blind vulnerabilities — starting with blind SSRF — by observing the target call back to its own out-of-band listener, correlated by a unique token.
---

Some vulnerabilities are **blind**: the server performs an action an attacker
controls, but the result never comes back in the response. Blind SSRF is the
classic case — a parameter makes the server fetch a URL, but you never see what it
fetched. A reflected check cannot confirm it.

Scout confirms these **out-of-band** (OAST). It starts its **own** listener,
injects a URL pointing at it (carrying a unique token) into candidate parameters,
and if the target calls the listener back, the vulnerability is **confirmed** —
the server fetched a URL Scout chose. This is detection, not exploitation: Scout
only observes the callback.

Nothing leaves your environment — the listener is Scout's own, not a third-party
interaction service.

## Running it

`app.blind-ssrf` runs in **active** mode:

```bash
scout scan --target http://localhost:3000 --mode active --env dev
```

For a **local** target it works out of the box: Scout binds a loopback listener
the app can reach.

For a **remote** target, the listener must be reachable *by the target*. Set
`SCOUT_OOB_ADDR` to a base URL the target can call back on, and Scout binds that
port:

```bash
SCOUT_OOB_ADDR=http://your-scanner-host:9999 \
  scout scan --target https://staging.example.com --mode active --env staging --allow-active
```

If the target cannot reach the listener, Scout simply reports nothing for this
check — it never claims a blind finding it could not observe.

## What you get

A confirmed finding names the parameter and the source of the callback:

```
[high/confirmed] Blind server-side request forgery in parameter url
    target made an out-of-band request to Scout's OAST listener from 10.0.0.12:4455
```

This complements the reflected SSRF check (`app.ssrf`), which confirms SSRF
against the cloud metadata service when its response is reflected back. Together
they cover both the visible and the blind case.
