# Writing a collector

A **collector** is a package of one or more **checks**. A check is anything
that implements `core.Check` and emits the shared `core.Finding`. This is the
one extension point that matters: everything else in Scout — scoring, dedupe,
history, the dashboard, reports, SARIF, alerts — works automatically once a
check produces findings.

## The `core.Check` interface

```go
type Check interface {
    ID() string                 // stable, namespaced: "headers.nosniff", "tls.expired"
    Category() Category         // CategoryHeaders, CategoryTLS, CategoryApp, ...
    Mode() Mode                 // the most aggressive mode this check uses
    Run(ctx context.Context, t Target) ([]Finding, error)
}
```

- **`ID()`** is `collector.check-name`, lowercase and dotted. It is part of the
  finding fingerprint, so never change it once released.
- **`Mode()`** is the single most important method for safety. Declare the
  most aggressive mode the check ever uses (`ModePassive`, `ModeSafe`,
  `ModeActive`, `ModeIntrusive`). The engine will skip the check when the
  environment caps below it. A passive check must send no attack traffic.
- **`Run`** returns findings and an error. A returned error is recorded
  against the scan, never fatal; a panic is recovered. Honor `ctx`
  cancellation and deadlines.

Two optional interfaces enrich a check:

```go
type Describer interface { Description() string }                 // plan/dashboard text
type StandardsMapper interface { OWASP() []string; ASVS() []string } // compliance view
```

## Rules every check must follow

1. **Only make requests through the guarded client.** Use
   `core.HTTPClient(ctx)` for every outbound request. It enforces scope, rate
   limits, the scan window and the kill switch, and signs the request. A
   request made any other way either bypasses safety or (outside a scan) is
   refused.
2. **Live under `collectors/`.** The shared HTTP helper is
   `collectors/internal/httpx`, an internal package, so checks belong under
   `collectors/...`.
3. **Be deterministic.** No reliance on time or map ordering in output. Set a
   stable `Severity`, `Confidence`, `CWE`/`OWASP`, and a `Remediation`.
4. **Share expensive work.** `httpx.Get` memoizes a fetch for the whole scan,
   so ten checks reading the home page cause one request.
5. **Register in `init()`** with `core.Register`, and pull the collector into
   builds by importing it (see "Wiring in", below).

## Helpers

| Helper | Use |
|--------|-----|
| `httpx.Get(ctx, url)` | Fetch a page once per scan; returns status, headers, cookies, body and request/response evidence. |
| `httpx.Do(ctx, method, url, header)` | A one-off request (not memoized). |
| `httpx.Resolve(t, path)` / `httpx.Asset(t, u)` | Build a URL on the target and a `core.Asset` with the right exposure. |
| `core.Memo(ctx, key, fn)` | Memoize any expensive lookup (TLS handshake, DNS) for the scan. |
| `remediation.SetHeader(name, value)` | Ready-made Gin/Nginx/Caddy/Next.js fix snippets for a response header. |

## A worked example (passive)

A minimal check that flags a response missing
`X-Content-Type-Options: nosniff`. It reads one ordinary GET — no attack
traffic — so its mode is `ModePassive`.

```go
// Package headers checks HTTP security-hardening headers. Passive: it reads
// one ordinary response, shared across checks via the scan cache.
package headers

import (
    "context"
    "strings"

    "github.com/MUKE-coder/scout/collectors/internal/httpx"
    "github.com/MUKE-coder/scout/core"
    "github.com/MUKE-coder/scout/remediation"
)

func init() { core.Register(NoSniff{}) }

// NoSniff flags a missing X-Content-Type-Options: nosniff header.
type NoSniff struct{}

func (NoSniff) ID() string            { return "headers.nosniff" }
func (NoSniff) Category() core.Category { return core.CategoryHeaders }
func (NoSniff) Mode() core.Mode         { return core.ModePassive }
func (NoSniff) Description() string     { return "Response is missing X-Content-Type-Options: nosniff" }
func (NoSniff) OWASP() []string         { return []string{"A05:2021"} }
func (NoSniff) ASVS() []string          { return []string{"V14.4.3"} }

func (NoSniff) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
    if t.URL == "" {
        return nil, nil // nothing to read for a repo-only target
    }
    page, err := httpx.Get(ctx, t.URL) // guarded + memoized
    if err != nil {
        return nil, err
    }
    if strings.EqualFold(strings.TrimSpace(page.Header.Get("X-Content-Type-Options")), "nosniff") {
        return nil, nil // present: no finding
    }
    f := core.Finding{
        Title:      "X-Content-Type-Options: nosniff is missing",
        Category:   core.CategoryHeaders,
        Severity:   core.SeverityLow,
        Confidence: core.ConfidenceConfirmed,
        Asset:      httpx.Asset(t, page.URL),
        Evidence:   core.Evidence{Request: page.Request, Response: page.Response},
        CWE:        []string{"CWE-693"},
        OWASP:      []string{"A05:2021"},
        Remediation: core.Remediation{
            What:   "Responses do not send X-Content-Type-Options: nosniff.",
            Why:    "Browsers may guess a response's type, so an uploaded file can be run as script or stylesheet.",
            How:    remediation.SetHeader("X-Content-Type-Options", "nosniff"),
            Effort: core.EffortS,
            References: []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"},
        },
    }
    return []core.Finding{f}, nil
}
```

`Run` does **not** set `Fingerprint`, `Status`, `FirstSeen` or `LastSeen` —
the engine fills those. `CheckID` is also stamped by the engine from `ID()`,
so a finding from one check cannot be mislabeled.

## Modes by example

| Mode | Example checks |
|------|----------------|
| Passive | security headers, cookie flags, TLS version/expiry, DNS/email records, exposed `.git`/`.env` presence by status code, reading the Gin route table |
| Safe | reflection canaries, GET-only fuzzing, version fingerprinting, open-redirect probes |
| Active | injection payloads, auth-bypass, IDOR with test accounts, SSRF |
| Intrusive | brute force, load tests, state-changing requests |

Choose the lowest mode that does the job; it widens where the check may run.

## Testing a collector

Drive it with a `httptest.Server` and the guarded client, the way the
`collectors/internal/httpx` tests do:

```go
ctx := core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
findings, err := NoSniff{}.Run(ctx, core.Target{URL: srv.URL, Environment: core.EnvDev})
```

Assert on severity, asset and remediation. Keep assertions deterministic.

## Wiring in

Checks register themselves in `init()`, so a collector only runs if its
package is imported. Create `collectors/all/all.go` that blank-imports every
collector, and have the CLI and server import `collectors/all`:

```go
// Package all pulls in every built-in collector so init() registration runs.
package all

import _ "github.com/MUKE-coder/scout/collectors/headers"
// ... one line per collector
```

Add one line per collector here and the whole product — scans, scoring, the
dashboard, SARIF, the compliance view — picks it up with no other change.
```
