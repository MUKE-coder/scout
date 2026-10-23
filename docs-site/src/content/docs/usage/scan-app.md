---
title: Scan a running app
description: Black-box scanning — point Scout at a live URL to find missing headers, exposed files, injectable parameters and weak auth.
---

A **black-box** scan points Scout at a running app by URL. Scout crawls what it
can reach and runs the checks allowed by your [mode and environment](/start/modes/).

## The basic scan

```bash
scout scan --target http://localhost:3000
```

This runs **safe** mode: the crawl plus non-mutating checks (headers, cookie
flags, exposed `.env`/`.git`/backups, CORS, GraphQL introspection, version
disclosure, directory listings, mixed content, and more). You get a graded
report.

## Go deeper on a local app

On localhost you can run the full active suite with no ownership proof:

```bash
scout scan --target http://localhost:3000 --mode active --env dev
```

Active adds the injection and auth probes: SQL injection, OS command injection,
open redirect, reflected XSS, SSRF, path traversal, and (with
[test identities](/usage/idor/)) IDOR.

## Scan a public host

A non-local target in active mode needs [ownership verification](/start/ownership/)
and `--allow-active`:

```bash
# safe is fine with no extra steps
scout scan --target https://staging.example.com --env staging

# active requires the ownership token + opt-in
scout scan --target https://staging.example.com --mode active --env staging --allow-active
```

## Scan several targets at once

`--target` is repeatable:

```bash
scout scan \
  --target http://localhost:3000 \
  --target http://localhost:3000/admin
```

## Preview without sending anything

```bash
scout scan --target https://example.com --mode active --env prod --dry-run
```

`--dry-run` lists every check that would run and every one it would skip (with
the reason), without making a request.

## Reading the report

Findings are grouped by severity (Critical → Info) and carry a **confidence**
(Confirmed / Likely / Possible), a CWE and OWASP tag, evidence, and a fix. At the
end, Scout prints a **letter grade** for the categories it assessed.

Want the data instead of the report? See [Output: JSON, SARIF, reports](/usage/output/).
