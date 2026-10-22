# Safety model

The same payload that is fine against `localhost` can corrupt data in
production. So **every check declares a mode**, and **every environment caps
the mode it will run**.

## Modes

| Mode | What it does |
|------|--------------|
| **Passive** | Reads headers, TLS, DNS, config, the route table. No attack traffic. |
| **Safe** | Harmless probes: reflection canaries, GET-only fuzzing, version checks. |
| **Active** | Real injection payloads, auth-bypass attempts, IDOR with test accounts. |
| **Intrusive** | Brute force, load tests, state-changing requests. |

## Environment caps

| Environment | Cap without opt-in | With per-target opt-in |
|-------------|--------------------|------------------------|
| `dev` | Intrusive | Intrusive |
| `staging` | Active | Intrusive |
| `prod` | Safe | Active (never Intrusive) |

A check above the cap is **skipped and reported as skipped**, with the reason.
Unknown environments are treated as production.

## The guard

Every request a check makes goes through one guarded HTTP client, which
enforces, in order:

1. **Kill switch** — a global stop; engaging it fails new requests at once and
   blocks new scans.
2. **Scan window** — an optional daily time range (with timezone and days);
   it fails closed on a malformed window.
3. **Scope** — an allowlist of hosts (exact or `*.` wildcard) and path
   prefixes; it defaults to the target's own host, never wider.
4. **Rate limit** — per-host requests per second.

A check that tries to make a request outside a scan gets a client that
refuses every request, so it can never send unguarded traffic.

## Ownership verification

Before active (or intrusive) mode on a non-local host, Scout requires proof of
control: a DNS `TXT` record (`scout-verify=<token>` on the host or
`_scout-verify.<host>`) or the token at `/.well-known/scout-verify.txt`. Run
`scout ownership --target <url>` to print the token. Unverified targets drop
to safe mode with an explanation. Successful verification is cached.

## Signed self-test header

Every outbound scan request carries `X-Scout-Scan: v1;ts=…;scan=…;sig=…`, an
HMAC over the method, host and path with a short validity window. Sentinel (or
any app) can verify it with the `selftest` package to tell Scout's traffic
apart from a real attacker's.

## Dry run

`scout scan --dry-run` prints exactly which checks would run, at which mode,
against which target, and sends nothing. It uses the same policy code as a
real scan, so the plan always matches.
