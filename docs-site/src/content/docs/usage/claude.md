---
title: Use Scout with Claude
description: Already have Claude? Install the Scout skill and just ask — "scan my app", "check this repo for vulnerabilities" — and Claude runs Scout correctly and acts on the results.
---

If you already use **Claude** (Claude Code), you can drive Scout in plain English.
Scout ships a **Claude skill** that teaches Claude how to install Scout, pick the
right scan for your situation, read the grade and findings, and apply fixes — so
you just ask.

```text
You:  scan my app at http://localhost:3000 and fix the worst issues
You:  is this repo safe to ship? check dependencies and secrets
You:  sweep my home network for exposed databases
You:  generate an SBOM for this project
```

## Install the skill

**With the [Skills CLI](https://skills.sh):**

```bash
npx skills add https://github.com/MUKE-coder/scout --skill scout
```

Add `--global` for a user-level install that works in every project.

**Or by hand** — copy the skill into your project (or `~/.claude/skills/`):

```bash
mkdir -p .claude/skills
cp -r path/to/scout/skills/scout .claude/skills/scout
```

The skill lives in the Scout repo at [`skills/scout/SKILL.md`](https://github.com/MUKE-coder/scout/tree/main/skills/scout).

## What Claude will do

With the skill installed, Claude will:

1. **Install Scout** if it is missing (one-liner), or use the one you have.
2. **Choose the scan** — a URL for a running app, `--repo` for source (local path or
   a GitHub URL it clones), `--network` for a subnet, `--sbom` for a bill of
   materials — and add `--serve` to open the dashboard or `--json` to parse results.
3. **Read the grade and the "fix next" list**, prioritising `[Exploited]`/KEV
   findings that are being exploited in the wild.
4. **Apply the remediation** each finding carries, then **re-scan** to confirm it is
   gone.

It follows Scout's safety rules: default scans are non-destructive, active probes
are for local/dev or ownership-verified targets, and it will ask before sweeping a
network that is not clearly yours.

## Prefer the dashboard?

You do not need Claude to use Scout — everything the skill does, you can run
yourself. The skill just makes it conversational. Run any scan with `--serve` to
explore results in the [dashboard](/usage/dashboard-tour/).
