---
title: Source scan
description: Point Scout at the lab's source to catch committed secrets, the insecure Dockerfile, weak crypto and dangerous sinks.
---

The black-box scan only sees what the app serves. A **source** scan reads the
lab's files on disk and catches a different class of problems — the ones you want
caught before anything is deployed.

## The scan

```bash
go run ./cmd/scout scan --repo ./lab --mode safe --env dev
```

No running app is needed for this one.

## What it finds

| File / pattern | Finding | Check |
|---|---|---|
| `.env` (committed) | Hard-coded secrets (`DB_PASSWORD`, `JWT_SECRET`, `API_KEY`) | `code.secrets` |
| `Dockerfile` | Root user, unpinned base image, secret in `ENV` | `code.dockerfile` |
| `lib/crypto.js` | MD5 / SHA-1 hashing, `Math.random` tokens | `code.weak-crypto`, `code.insecure-random` |
| `lib/logger.js` | Password / token written to logs | `code.secret-logging` |
| `/search`, API routes | `eval` / `exec` / raw HTML sinks | `code.dangerous-sink` |
| `package.json` | Loose dependency ranges | `code.unpinned-deps` |

If the lab were a Go module with vulnerable dependencies, `code.go-vulncheck`
would also flag reachable CVEs — see [Scan a repo](/usage/scan-repo/).

## Combine both

Run the live checks and the source checks together:

```bash
go run ./cmd/scout scan --target http://localhost:4000 --repo ./lab --mode active --env dev
```

One command, one report, covering both the running surface and the source.
