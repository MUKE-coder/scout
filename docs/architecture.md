# Architecture

Scout's value is the orchestration layer — the unified model, scoring, fixes
and UI — not any single engine. Collectors are pluggable; everything else is
built around one findings model.

## Packages

| Package | Responsibility |
|---------|----------------|
| `core` | Shared types: `Finding`, `Asset`, `Check`, `Registry`, `Mode`, `Category`, `Scope`, the guarded-client context and the per-scan cache. |
| `engine` | The scan loop: mode policy, the request guard (scope, rate limit, window, kill switch), ownership verification, worker pool, findings pipeline and event bus. |
| `scoring` | Risk weights, exponential-decay category scores, grade caps, fix-next ranking, criticality rules. |
| `remediation` | Stack detection and the Markdown fix renderer. |
| `storage` | `Store` interface with an in-memory ring buffer and pure-Go SQLite. |
| `report` | Terminal, JSON, SARIF, HTML report, scan diff, attack-surface tree, compliance. |
| `selftest` | Signs and verifies the `X-Scout-Scan` header. |
| `alerts` | Slack, Discord, email and signed webhook notifications. |
| `integrations` | Optional Pulse and Sentinel links. |
| `ai` | Redaction and the Vercel AI Gateway client. |
| `api` | REST API and the live WebSocket. |
| `cli` | The `scout` command. |
| `ui` | The embedded React dashboard (`ui/dashboard` source, `ui/dist` build). |
| root (`scout`) | `Config`, `Mount`, lifecycle, logging, retention and wiring. |

## Data flow of a scan

1. `engine.Run` validates the target, checks the kill switch and scan window,
   then builds a **guarded HTTP client** for the scan and attaches it (and a
   per-scan cache) to the context.
2. A **policy** caps the requested mode by environment and opt-in, and
   requires proven ownership before active mode on a non-local host.
3. Checks whose mode fits run on a bounded **worker pool**; each has a timeout
   and panic recovery. Every outbound request passes through the guard
   (kill → window → scope → rate limit) and is signed.
4. Findings are **deduplicated** by fingerprint; first-seen and accepted-risk
   decisions carry over from the previous scan.
5. The scan is **scored**, persisted, and its progress and findings are
   published on the event bus (consumed by the WebSocket, alerts and
   integrations).

## The findings model

Every collector emits the same `core.Finding`. Its **fingerprint** —
`checkID + asset + location`, ignoring evidence and severity — is stable
across scans, which is what makes new/fixed/regressed diffs, dedupe and
history possible.

## Adding a collector

Implement `core.Check` (`ID`, `Category`, `Mode`, `Run`) and register it in
`init()` with `core.Register`. In `Run`, make every HTTP request through
`core.HTTPClient(ctx)` so it is guarded and signed; use `core.Memo` to share
fetches within a scan. Attach a deterministic `Remediation`. Optionally
implement `core.Describer` (plan text) and `core.StandardsMapper` (OWASP/ASVS
for the compliance view).
