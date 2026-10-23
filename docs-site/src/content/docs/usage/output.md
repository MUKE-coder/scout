---
title: "Output: JSON, SARIF, reports"
description: Print the graded terminal report, emit machine-readable JSON, write SARIF 2.1.0 for code scanning, or re-print any saved scan.
---

Scout can speak to humans and to machines. By default it prints a graded terminal
report; flags switch it to JSON or SARIF.

## The terminal report (default)

```bash
scout scan --target http://localhost:3000
```

Findings grouped by severity, each with confidence, CWE/OWASP, evidence and a fix,
followed by a **letter grade** for the categories assessed.

## JSON

```bash
scout scan --target http://localhost:3000 --json
```

Emits the full scan result — target, mode, findings, score, grade — as JSON on
stdout. Pipe it into `jq` or your own tooling:

```bash
scout scan --repo . --json | jq '.findings[] | select(.severity=="high") | .title'
```

## SARIF 2.1.0

```bash
scout scan --repo . --sarif scout.sarif
```

Writes [SARIF](https://sarifweb.azurewebsites.net/) alongside the normal output,
ready to upload into GitHub code scanning (see [Gate your CI](/usage/ci/)) or any
SARIF-aware viewer.

You can combine it with `--json` or the report — `--sarif` is additive.

## HTML / re-printing a scan

Every scan saved to the history DB can be re-printed later by id:

```bash
scout report <scan-id>
```

Run `scout report` with no id to list recent scans. See
[Scan history & diff](/usage/history/).

## Keeping (or not keeping) history

Results are saved to the SQLite file named by `--db` (default `scout.db`). To keep
nothing on disk:

```bash
scout scan --target http://localhost:3000 --db ""
```
