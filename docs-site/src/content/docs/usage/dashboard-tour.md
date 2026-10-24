---
title: Dashboard tour
description: A page-by-page walk through the Scout dashboard — what each page is for and how to read the numbers on it.
---

Run `scout serve` (or `scout scan --serve`) and open the URL it prints — the
dashboard is compiled into the binary, so there is nothing else to host. Each
section below explains what the page is **for** and how to **read** it.

## Signing in

The dashboard is protected by a username and password.

- **Default login (dev only):** `admin` / `scout`.
- Outside the `dev` environment Scout **refuses** to serve with the defaults —
  set your own in `scout.yaml`:

```yaml
username: admin
password: "a-strong-password"
jwt_secret: "a-long-random-string"   # keeps sessions across restarts
```

Run `scout init` to generate a `scout.yaml` with these (and every other setting)
already filled in at their defaults, then edit what you need.

## Overview

**Purpose:** the health of one target at a glance — pick the target top-right.

![Scout dashboard overview](/screens/overview.png)

**How to read it:**
- **Grade ring** — the overall score out of 100 and a letter grade.
  ✅ **A / B** is healthy · ⚠️ **C** has gaps · ❌ **D / F** needs attention now.
- **Score, last 30 days** — the trend. ✅ rising or flat-high is good; ❌ a drop
  means new findings since the last scan. (It appears once you have ≥2 scans.)
- **Severity row** (`2 high · 4 medium · …`) — counts by severity. Any
  **critical** or **high** is ❌ fix-first; **low / info** are ✅ usually safe to
  schedule.
- **Categories** — per-area sub-scores; the lowest bar is where to look next.
- **Fix next** — the highest-impact fixes, ranked by how many points they recover.

### Scan coverage

Scout is a **diagnostic tool**, so the Overview also shows how thoroughly a target
has been examined and what to run next.

![Scan coverage panel](/screens/coverage.png)

**How to read it:**
- The **progress bar** (e.g. *1 of 4 diagnostics · 25%*) is how many of the
  diagnostic dimensions you've run for this target.
- ✅ a dimension with a check is **done**; ⬜ one without is **recommended next** —
  each says exactly **what it diagnoses** (injection, source & dependencies, …).
- For a recommended dimension you get either a **Run** button (for a configured
  target — it starts the scan right here) or the **exact command** to copy.

**What to do:** work down to 100% — run an **active** scan for injection/auth, a
`--repo` scan for secrets and CVEs, and a second scan to establish a trend.

## Findings

**Purpose:** every open finding, with filters to slice by severity, category,
status, change and target. Click a row for evidence, CWE/OWASP and the fix.

![Findings page](/screens/findings.png)

**How to read it:**
- **Severity dot** — red = critical/high (❌ act first), amber = medium,
  blue/grey = low/info.
- **Change** — ❌ **New** or **Regressed** appeared since the last scan;
  ✅ **Fixed** is gone. Filter to **New** in CI to see only what a change introduced.
- **Status** — **Open** (❌ still live) vs **Accepted risk / False positive**
  (✅ triaged — you marked it, with a reason).

**What to do:** sort by severity, open a finding to read its **cause and fix**,
apply it, and re-scan — the Change column will flip it to ✅ **Fixed**.

### Export

The **Export** menu downloads the findings as **Markdown**, **HTML** or **plain
text** (plus JSON / CSV) — each with the evidence and the fix — to hand to a
developer or drop into a PR or ticket.

![Export menu](/screens/export.png)

:::tip
You can also export from the CLI, straight into your working directory:

```bash
scout scan --target https://example.com --export md,html
# writes scout-report.md and scout-report.html
```
:::

## Attack surface

**Purpose:** a map of everything Scout reached — domain → host → service (port) →
route — so you can see what's exposed.

![Attack surface map](/screens/surface.png)

**How to read it:**
- **The number on each node is the count of _open findings_ at or below it.**
  So a domain shows the total across all its hosts; a host shows its total; a
  service (`https :443`) shows the findings on that port; a route shows its own.
  - ✅ **A smaller tree with low numbers** = a small, clean attack surface.
  - ❌ **A big number** points you straight to the host/port/route carrying the
    most risk — start there.
- Also watch for things that shouldn't be exposed at all: ❌ an open **`:22`
  (SSH)**, admin UIs (`/sentinel/ui`, `/pulse/ui`), or **deprecated API
  versions** (`/api/v1` still live next to `/api/v2`).

**What to do:** open the node with the highest number, jump to those findings,
and fix or lock down the exposed services you didn't expect.

## Compliance

**Purpose:** your open findings mapped onto the **OWASP Top 10 (2021)** (and ASVS
below it), plus how much of each category Scout's checks actually cover.

![Compliance / OWASP Top 10 coverage](/screens/compliance.png)

**How to read it:**
- **Checks** column — how many of Scout's checks map to that category. It's a
  **coverage** number, not a score: higher means Scout tests that area more
  thoroughly (e.g. A05 Security misconfiguration has the most checks). A category
  with a low number is simply tested by fewer checks.
- **Per-target columns** — the number of **open findings** your target has in that
  category:
  - **`·` (a dot) = 0 open findings → ✅ clean for that category.**
  - **A number (e.g. `11`, highlighted) = ❌ that many open findings → investigate.**
- The intro line (“*45 of 63 checks declare mappings; 10 of 10 Top 10 categories
  are covered*”) tells you how complete the mapping itself is — ✅ 10/10 means no
  Top 10 category is a blind spot.

So on the screenshot, **A05 = 11 ❌** (fix these) while **A01, A03, A04 = · ✅**
(nothing open there right now).

**Pass or fail?** There's no single pass/fail stamp — read it per category:
- **`·` (dot) = ✅ pass** for that OWASP category: Scout tested it and found
  nothing open.
- **A number = ❌ fail** for that category: that many open findings — fix them to
  turn the cell back to a dot.
- A category Scout can't test (no mapped checks, rare here since 10/10 are
  covered) is simply blank — not a pass, just untested.

**What to do:** treat every non-dot cell as a to-do for that OWASP area; click
into Findings filtered by that category to see the specific issues and fixes.

## Live scan

**Purpose:** watch a scan run in real time — checks completing one by one — when
you start one from **New scan** or run `scout scan --serve`.

**How to read it:** ✅ a check that finishes with no finding is clean; ❌ one that
raises a finding streams in with its severity as it happens.

## History

**Purpose:** every saved scan with its grade and time.

![Scan history](/screens/history.png)

**How to read it:** compare grades down the list — ✅ the grade rising over time
is progress; ❌ a drop flags a regression. Pick two scans to
[diff](/usage/history/) and see exactly which findings appeared or were fixed.

## Settings

**Purpose:** the configuration Scout is running with — environment, mode, scope
and targets — read from `scout.yaml` and `SCOUT_*` environment variables.

![Settings](/screens/settings.png)

**How to read it:** it's read-only confirmation. ✅ **Environment cap** tells you
the most aggressive mode allowed here; ❌ **“No targets configured”** means the
dashboard can't start scans until you add targets to `scout.yaml` (run
`scout init` to scaffold it). Change anything in the file and restart.
