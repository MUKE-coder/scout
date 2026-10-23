---
title: Quickstart
description: Install Scout and run your first scan against a running app and a repo in under two minutes.
---

Scout is a single Go binary. Install it, point it at something, read the grade.

## 1. Install

```bash
go install github.com/MUKE-coder/scout/cmd/scout@latest
```

This puts `scout` on your `PATH` (in `$(go env GOPATH)/bin`). No account, no
config file required. See [Installation](/start/installation/) for other ways.

## 2. Scan a running app

Start your app locally, then point Scout at it:

```bash
scout scan --target http://localhost:3000
```

Scout crawls the surface, runs the safe-mode checks, and prints a graded report:
findings grouped by severity, each with a CWE/OWASP tag and a fix.

:::note
`--mode safe` is the default. Against **localhost** you can go further with
`--mode active --env dev` to run the injection and auth probes — no ownership
proof is needed for local targets. See [Modes & environments](/start/modes/).
:::

## 3. Scan a repository

Point Scout at a checkout to find secrets, insecure Dockerfiles, weak crypto,
dangerous sinks and reachable CVEs in your Go dependencies:

```bash
scout scan --repo .
```

You can combine both in one scan:

```bash
scout scan --target http://localhost:3000 --repo . --mode active --env dev
```

## 4. Gate your CI

Fail a pull request when Scout finds something at or above a severity:

```bash
scout ci --repo . --fail-on high
```

It exits non-zero on a qualifying finding, so the build turns red. See
[Gate your CI](/usage/ci/).

## 5. See it in the dashboard

```bash
scout serve
```

Opens an embedded dashboard with scan history, findings and scheduled scans.

## Where to go next

- Try every check against the [deliberately-vulnerable lab app](/lab/overview/).
- Learn the [modes and environments](/start/modes/) that keep scans safe.
- Browse the full [checks catalog](/reference/checks/).
