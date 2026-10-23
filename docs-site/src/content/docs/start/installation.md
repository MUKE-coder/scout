---
title: Installation
description: Install Scout with go install, build it from source, or run it without installing. Requirements and verification.
---

Scout is a single, statically-linked Go binary with no runtime dependencies
(pure-Go SQLite, no CGo). Pick whichever install suits you.

## Requirements

- **Go 1.24+** to install from source or with `go install`.
- A terminal. Scout runs on Linux, macOS and Windows.
- For the **reachable-CVE check**, the optional [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
  binary matching your Go toolchain. Scout skips the check gracefully if it is
  absent.

## go install (recommended)

```bash
go install github.com/MUKE-coder/scout/cmd/scout@latest
```

The binary lands in `$(go env GOPATH)/bin`. Make sure that is on your `PATH`.

Pin a release instead of `@latest`:

```bash
go install github.com/MUKE-coder/scout/cmd/scout@v0.3.0
```

## From source

```bash
git clone https://github.com/MUKE-coder/scout
cd scout
go build -o scout ./cmd/scout
./scout version
```

## Run without installing

```bash
go run github.com/MUKE-coder/scout/cmd/scout@latest scan --target http://localhost:3000
```

## Verify

```bash
scout version
```

You should see the version string (for example `scout 0.3.0`).

## Next

Head to the [Quickstart](/start/quickstart/) to run your first scan, or read how
[modes & environments](/start/modes/) keep scans safe.
