---
title: Scan history & diff
description: Scout saves scans to local SQLite. Compare two scans to see what changed, re-print old reports, and prune old history.
---

Scout saves every scan to a local SQLite file (default `scout.db`). That history
powers the dashboard charts, the `--new-only` CI gate, and the diff command.

## Where history lives

```bash
scout scan --repo . --db scout.db     # default
scout scan --repo . --db ""           # keep nothing
```

The file is pure-Go SQLite — no external database, nothing leaves your machine.

## Diff two scans

```bash
scout diff <scan-a> <scan-b>
```

Shows what changed between two runs: findings that appeared (regressions), ones
that were fixed, and ones that persist. This is the same comparison `scout ci
--new-only` uses to fail only on new or regressed findings.

## List and re-print

```bash
scout report              # list recent scans with their ids
scout report <scan-id>    # re-print a saved scan's report
```

## Prune old scans

```bash
scout prune
```

Deletes scans older than the retention period (default 90 days; configurable via
`retention` in the [config](/reference/configuration/)).

## Typical loop

```bash
# establish a baseline
scout scan --repo . --db scout.db

# later, after changes — fail only on new findings
scout ci --repo . --db scout.db --fail-on high --new-only

# see exactly what changed between the last two
scout diff <previous-id> <latest-id>
```
