---
title: Dashboard & scheduled scans
description: Run scout serve for an embedded dashboard with scan history, findings and recurring scheduled scans.
---

`scout serve` starts a local web server with an embedded React dashboard: scan
history, findings over time, and scheduled scans that run while it is up.

## Start it

```bash
scout serve
```

Then open the URL it prints. The dashboard is compiled into the binary — there is
nothing else to install or host.

## Credentials

The dashboard is protected by a username and password. In `dev` the defaults
(`admin` / `scout`) are allowed; **outside dev Scout refuses to serve with the
defaults** — set your own in the [config](/reference/configuration/):

```yaml
username: admin
password: "a-strong-password"
jwt_secret: "a-long-random-string"
```

## Scheduled scans

Define schedules in the config so `scout serve` runs them automatically:

```yaml
targets:
  - name: staging
    url: https://staging.example.com
    environment: staging

schedules:
  - name: nightly
    target: staging
    cron: "0 2 * * *"
```

Each run is saved to history, so you can [diff scans](/usage/history/) and the
dashboard can chart findings over time.

## Alerts

Scout can notify you about new or regressed findings after each saved scan (see
[Configuration](/reference/configuration/) for the `alerts` block).

## Scan windows

Restrict when scans may run (for example, off business hours) with a `window` in
the config, so a scheduled or triggered scan never fires at a bad time.
