# Stability

Scout follows [Semantic Versioning](https://semver.org/).

## Pre-1.0

While the major version is `0`, the Go API and the HTTP API may change
between **minor** versions (`0.1` → `0.2`). Patch releases (`0.1.0` → `0.1.1`)
are backward compatible. Pin a version if you depend on current behavior.

## What "1.0" will mean

Scout reaches `1.0.0` when its [definition of done](feature-checklist.md) is
met — in particular when the security collectors ship and Scout can scan both
a local Gin app and an arbitrary website and report real, fixable findings. A
scanner that cannot yet find vulnerabilities is deliberately **not** released
as `1.0`.

## Stable surfaces (even pre-1.0)

These are designed to be stable and are unlikely to break:

- The `core.Finding` shape and its JSON representation.
- The `core.Check` interface collectors implement.
- Finding fingerprints (so history survives upgrades).
- The `/scout` URL namespace and the SARIF output schema.

## Compatibility notes

- **No CGo.** Scout builds with `CGO_ENABLED=0` on Linux, macOS and Windows.
- **Embedded dashboard.** `ui/dist/` is committed; consumers never need Node.
- **Storage.** The SQLite schema is auto-migrated; downgrades are not
  supported.
