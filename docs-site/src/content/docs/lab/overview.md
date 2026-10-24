---
title: What the lab is
description: A deliberately-vulnerable Next.js app that ships in the Scout repo, both to learn by exploiting and as a test target for every Scout check.
---

The Scout repo ships a small, **deliberately-vulnerable** app under `lab/`. It is
in the spirit of [DVWA](https://github.com/digininja/DVWA) and
[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/): every "lab" is a
real, exploitable weakness you can poke at in the browser, and the whole app
doubles as a fixture that exercises Scout's collectors.

:::danger
**It is intentionally insecure.** Run it on **localhost only**. Never deploy it,
never expose it to a network, and never put real data in it.
:::

## Why it exists

- **Learn by exploiting.** Each lab page explains the weakness and how to fix it.
- **See Scout work.** Running Scout against the lab produces a rich, failing
  report — a great way to understand what each check catches and what a finding
  looks like.

## What's inside

A Next.js app (port 4000) with:

- Missing security headers and weak cookies across the whole app.
- Exposed files: `/.env`, `/.env.bak`, `/.git/config`, `/metrics`,
  `/swagger.json`, `/backup.sql`.
- Interactive labs: IDOR, broken access control, reflected XSS, CSRF, forgeable
  JWT, open redirect, permissive CORS.
- Vulnerable API routes: command injection, SSTI, XXE, mass assignment, business
  logic, deprecated API versions, host-header injection, stack-trace disclosure,
  GraphQL introspection.
- Committed secrets (`.env`), an insecure `Dockerfile`, weak crypto and dangerous
  sinks in the source — for the `--repo` checks.

## The fastest way in

```bash
scout lab
```

Scout clones the repo, runs a **source scan** on `lab/`, and prints the steps to
scan the **running app** too — so you can demo it in one command. The pages below
are the manual walkthrough.

## Next

1. [Run the lab](/lab/run/) (or just `scout lab`).
2. [Black-box scan](/lab/black-box/) it.
3. [Source scan](/lab/source/) it.
4. See [what each check catches](/lab/coverage/).
