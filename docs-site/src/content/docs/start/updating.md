---
title: Updating Scout
description: Scout keeps itself current — it checks for a new release and self-updates on your next run — or update on demand with scout update.
---

Scout keeps itself up to date.

## Automatic

On a normal command, Scout checks GitHub for a newer release **at most once a
day**. When one is out, it downloads it, replaces its own binary, and relaunches
your command on the new version — so the next time you run Scout after a release,
you are already on it. You will see:

```
Scout v0.5.0 is available (you have v0.4.16). Updating…
Updated to v0.5.0. Relaunching…
```

The check is quiet and safe: if GitHub is unreachable it is skipped, and it never
blocks or fails your command.

### When it does *not* auto-update

- In **CI** (the `CI` environment variable is set) — builds stay reproducible.
- For `scout serve` (long-running) and `scout ci`.
- For a local/dev build (no released version to compare).
- When you turn it off:

```bash
export SCOUT_NO_UPDATE=1
```

## On demand

```bash
scout update          # check and install the latest release
scout update --check  # only tell me if one is available
```

`scout update` works regardless of the auto-update setting, and replaces the
running binary in place (on Windows the old one is moved aside automatically).

## How it works

Scout downloads the release asset for your OS/architecture from
[GitHub Releases](https://github.com/MUKE-coder/scout/releases), verifies it is the
right artifact, and swaps it into place atomically. If anything goes wrong the
current binary is left untouched.
