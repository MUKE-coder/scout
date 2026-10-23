---
title: Black-box scan
description: Scan the running lab app with Scout in active mode and read the graded report of everything it finds.
---

With the [lab running](/lab/run/) on port 4000, scan it as a running app. Because
it is localhost, active mode needs no ownership proof.

## The scan

```bash
go run ./cmd/scout scan --target http://localhost:4000 --mode active --env dev
```

## What it finds

The lab is built to fail, so you get a rich report — an **F grade** with findings
across several categories, for example:

- **Headers** — no CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy or
  Permissions-Policy; cookies with no HttpOnly / Secure / SameSite.
- **Exposure** — `/.env`, `/.env.bak`, `/.git/config`, `/metrics`,
  `/swagger.json`, `/backup.sql` all reachable.
- **App** — reflected XSS on `/search`, open redirect on `/api/redirect`, a CSRF
  form on `/transfer`, stack-trace disclosure on `/api/debug`, host-header
  injection on `/api/reset`, version disclosure (`X-Powered-By: Next.js`).
- **Auth** — permissive CORS on `/api/data` (reflects Origin with credentials),
  a forgeable JWT (`alg:none`, no expiry) in the `session` cookie.
- **API** — GraphQL introspection enabled on `/api/graphql`, a deprecated
  `/api/v1/users` still live alongside `/api/v2/users`.

## Reading a finding

Each finding names the asset, a severity and confidence, the CWE/OWASP mapping,
the evidence Scout matched, and a concrete fix. The grade at the end summarizes
the categories Scout assessed.

## Go further

- IDOR needs test accounts to confirm — see [IDOR on the lab](/lab/idor/).
- Scan the lab's **source** for secrets and CVEs — see [Source scan](/lab/source/).
- The full mapping of lab weakness → Scout check is in
  [What each check catches](/lab/coverage/).
