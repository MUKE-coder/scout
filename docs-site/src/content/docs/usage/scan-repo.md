---
title: Scan a repo (source)
description: Source and supply-chain scanning — point Scout at a checkout to find secrets, insecure Dockerfiles, weak crypto, dangerous sinks and reachable CVEs.
---

A **source** scan points Scout at a local repository with `--repo`. It reads the
files on disk — no running app required — to find problems you want caught before
deploy.

## The basic scan

```bash
scout scan --repo .
```

Point it anywhere:

```bash
scout scan --repo /path/to/project
```

## Scan straight from a Git URL

`--repo` also accepts a repository URL. Scout clones it to a temporary checkout,
scans it, and removes it afterwards — nothing is left on disk:

```bash
scout scan --repo https://github.com/MUKE-coder/gorm-studio
```

- **Public repos** work with no setup.
- **Private repos** use your existing git credentials: a credential helper
  (`gh auth login`), an SSH URL with your key (`git@github.com:owner/repo.git`),
  or a token in `SCOUT_GIT_TOKEN` (or `GITHUB_TOKEN`) for an `https://` URL — the
  last is handy in CI. Interactive prompts are disabled, so a repo you cannot read
  fails fast with a clear message instead of hanging.

The target is named after the repo (`owner/repo`), so it reads clearly in the
report and the dashboard.

## What the repo checks find

| Check | Catches |
|---|---|
| `code.secrets` | Hard-coded API keys, tokens and passwords committed to the repo |
| `code.dockerfile` | Root user, unpinned base images, secrets baked into `ENV` |
| `code.weak-crypto` | MD5 / SHA-1 / DES / RC4 used for security |
| `code.insecure-random` | `math/rand` / `Math.random()` used for tokens |
| `code.dangerous-sink` | `eval`, `child_process`, `exec.Command`, `dangerouslySetInnerHTML`, unsafe deserialization |
| `code.secret-logging` | Passwords / tokens written to logs |
| `code.unpinned-deps` | Loose version ranges (`^`, `~`, `*`, `latest`) in `package.json` |
| `code.vulnerable-deps` | **Known-vulnerable dependencies in any ecosystem** — npm, Go, PyPI, Composer, Cargo, RubyGems, NuGet, Maven (via OSV) |
| `code.go-vulncheck` | Known, **reachable** CVEs in Go dependencies (via `govulncheck`) |

## Exploitation intelligence (KEV + EPSS)

A long list of CVEs is noise unless you know which ones matter. Scout enriches
every `code.vulnerable-deps` finding with two independent exploitation signals:

- **CISA KEV** — the [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  catalog. If a CVE is here, it is **being exploited in the wild right now**.
  Scout marks it `[Exploited]`, escalates it to at least **High**, and sorts it to
  the top of "Fix next". Ransomware-campaign use is called out explicitly.
- **FIRST EPSS** — the [Exploit Prediction Scoring System](https://www.first.org/epss/):
  a probability (0–100%) that a CVE will be exploited in the next 30 days, with a
  percentile. Shown on each finding so you can triage the long tail.

Both feeds are cached on disk (`<user-cache>/scout/intel/`), so repeat scans are
fast and keep working offline for 24 hours after the first fetch. A senior
reviewer reads these first: a critical CVSS with no KEV and a tiny EPSS is often
less urgent than a "medium" that is in KEV.

## Reachable CVEs in Go dependencies

`code.go-vulncheck` runs [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
over your module and grades by **reachability**:

- **High / Confirmed** when a vulnerable function is actually called.
- **Medium / Likely** when the package is imported but the function is not reached.

It degrades gracefully: if the target is not a Go module, or `govulncheck` is not
installed, or the module cannot be analyzed, the check reports nothing rather than
failing the scan.

## Combine source and black-box

Run both against the same project in one scan — the source checks use `--repo`,
the live checks use `--target`:

```bash
scout scan --target http://localhost:3000 --repo . --mode active --env dev
```

## Next

- Wire this into CI: [Gate your CI](/usage/ci/).
- See it against a real repo: [Source scan of the lab](/lab/source/).
