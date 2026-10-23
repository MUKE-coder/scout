---
title: IDOR on the lab
description: A worked example — configure two test identities and have Scout confirm the IDOR at the lab's /api/users/[id] endpoint.
---

The lab's `/api/users/[id]` endpoint serves any user's object to any caller — a
textbook IDOR. Here is how to have Scout confirm it, end to end.

## 1. Why it needs config

`auth.idor` proves the bug by comparison: it confirms one identity owns an object,
then checks whether a *different* identity can read the same object. That needs two
[test identities](/usage/idor/). Without them the check reports nothing.

## 2. Configure two identities

Create a config file (for example `scout.lab.yaml`) with two throwaway accounts,
each owning a different user object:

```yaml
targets:
  - name: lab
    url: http://localhost:4000
    environment: dev

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

:::note
Use whatever the lab accepts to distinguish the two callers. The point is that
`alice` owns `/api/users/1` and `bob` owns `/api/users/2`; a correct app would
stop each from reading the other's.
:::

## 3. Run the active scan

```bash
go run ./cmd/scout scan --config scout.lab.yaml --mode active --env dev
```

## 4. The finding

Because the lab enforces no ownership check, Scout confirms that `bob` can read
`alice`'s object (and vice versa) and reports a **High / Confirmed** IDOR
(CWE-639, OWASP A01:2021). The probe is read-only, compares bodies by hash, and
never stores their contents.

## What a fixed app looks like

If the lab checked ownership on every object access, each identity would get only
its own object (or a 403 on the other's), and Scout would report nothing — exactly
the behaviour you want in production.
