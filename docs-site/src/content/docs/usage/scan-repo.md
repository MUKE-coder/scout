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
| `code.go-vulncheck` | Known, **reachable** CVEs in Go dependencies (via `govulncheck`) |

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
