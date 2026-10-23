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

Then open the URL it prints — the dashboard lives at `/scout/ui/`, but the bare
root (`http://localhost:9090/`) now redirects there too, so either works. The
dashboard is compiled into the binary — there is nothing else to install or host.
`scout serve` reads `scout.db` from the current directory (change the file with
`--db`, the port with `--addr`).

**Stopping it:** the server runs in the foreground until you press **Ctrl+C**,
which shuts it down gracefully. (Running from a non-default directory? It only
sees the `scout.db` in that directory — point it with `--db <path>`.)

:::tip
`scout serve` is a **separate server** — a scan on its own does not start it. To
go from a scan straight to the dashboard in one step, add `--serve`:

```bash
scout scan --target https://example.com --serve
```

This runs the scan, then boots the dashboard on the same history database.
:::

## Export findings

On the dashboard's **Findings** page, the **Export** menu downloads the findings
as Markdown, HTML or plain text (plus JSON/CSV) — each with the evidence and the
fix — to hand to a developer or drop into a PR or ticket.

## Credentials

The dashboard is protected by a username and password. In `dev` the default
login is **`admin` / `scout`**; **outside dev Scout refuses to serve with the
defaults** — set your own in the [config](/reference/configuration/). Run
`scout init` to generate a `scout.yaml` with these (and every other setting)
already filled in, then edit it:

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
