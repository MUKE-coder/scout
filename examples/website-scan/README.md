# Example: scan an arbitrary website

Scout needs nothing installed on the target. Point it at a URL and it crawls,
inspects and reports — no app integration required.

```bash
# A safe, read-only scan (default mode). Nothing destructive is ever sent.
scout scan --target https://example.com --mode safe

# See exactly what would run, against which target, at which mode — and send
# nothing:
scout scan --target https://example.com --mode active --env prod --dry-run

# Machine-readable output:
scout scan --target https://example.com --json  > result.json
scout scan --target https://example.com --sarif result.sarif   # GitHub code scanning
```

## Active scans need proof you own the target

Active and intrusive modes against a non-local host require ownership
verification. Print the token and where to publish it:

```bash
scout ownership --target https://example.com
```

Publish the token as a DNS `TXT` record or at
`/.well-known/scout-verify.txt`, then add `--allow-active`.

## Mode is always capped by the environment

| Environment | Highest mode without opt-in | With `--allow-active` |
|-------------|-----------------------------|-----------------------|
| `dev`       | intrusive                   | intrusive             |
| `staging`   | active                      | intrusive             |
| `prod`      | safe                        | active (never intrusive) |

> **Status:** the scan engine, scoring, reports and safety controls are in
> place, but the security **checks** are not yet bundled, so a scan currently
> reports no findings. See the repository README for the current state.
