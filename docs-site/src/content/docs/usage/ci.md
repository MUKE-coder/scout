---
title: Gate your CI
description: Use scout ci to fail a build on findings at or above a severity, with SARIF upload and new-only gating.
---

`scout ci` runs a scan and **exits non-zero** when it finds something worth
blocking the build. That is the only difference from `scout scan` — same checks,
same flags, plus a failure threshold.

## The command

```bash
scout ci --repo . --fail-on high
```

| Flag | Default | Meaning |
|---|---|---|
| `--fail-on <severity>` | `high` | Fail when a finding is at or above this severity (`info`,`low`,`medium`,`high`,`critical`) |
| `--new-only` | off | Only count findings that are new or regressed since the last saved scan |

All the `scan` flags apply too (`--target`, `--repo`, `--mode`, `--env`,
`--sarif`, `--db`, …).

## Baseline, then new-only

On an existing project you will have findings on day one. Record a baseline, then
gate on **new** regressions so the build only fails on things this change
introduced:

```bash
# once, to establish the baseline in the history DB
scout scan --repo . --db scout.db

# in CI, from then on
scout ci --repo . --db scout.db --fail-on high --new-only
```

## GitHub Actions

```yaml
name: scout
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.26" }
      - run: go install github.com/MUKE-coder/scout/cmd/scout@latest
      - run: scout ci --repo . --fail-on high --sarif scout.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scout.sarif
```

The `--sarif` output lands in GitHub's **Security → Code scanning** tab. See
[Output](/usage/output/) for the SARIF details.

## Scanning a deployed preview

If your CI spins up a preview URL, add a black-box scan too. Remember a public
host in active mode needs [ownership verification](/start/ownership/):

```bash
scout ci --target "$PREVIEW_URL" --env staging --fail-on high
```
