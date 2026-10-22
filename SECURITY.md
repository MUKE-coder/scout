# Security policy

## Reporting a vulnerability

Please report security issues privately. Open a
[GitHub security advisory](https://github.com/MUKE-coder/scout/security/advisories/new)
for the repository, or email the maintainer listed on the GitHub profile.
Do not open a public issue for an undisclosed vulnerability.

Please include steps to reproduce, affected versions, and impact. We aim to
acknowledge reports within a few days.

## Supported versions

While Scout is pre-1.0, only the latest tagged release receives fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Scanning responsibly

Scout can send active traffic to targets. Use it only against systems you own
or are explicitly authorized to test.

Scout is built to make this safe by default:

- **Mode caps.** Every check declares a mode; every environment caps the mode
  it will run. Production never runs intrusive mode, and active mode in
  production requires an explicit per-target opt-in.
- **Ownership verification.** Active scans of a non-local host require a DNS
  `TXT` record or `/.well-known/scout-verify.txt` proving control of the
  target.
- **Scope, rate limits, windows, kill switch.** Scans stay within an allowlist
  of hosts and paths, are rate-limited, can be confined to a time window, and
  can be stopped instantly.
- **Signed self-test header.** Every outbound scan request carries a signed
  `X-Scout-Scan` header so a WAF such as Sentinel can recognize it.

## Handling of sensitive data

- Scout is self-hosted with no telemetry; scan data stays in your storage.
- Optional AI features redact evidence bodies, hosts, IPs, emails and tokens
  before any request leaves the process, and show exactly what was sent.
- Default dashboard credentials are refused outside development.
