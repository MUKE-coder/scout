# Collector build sheet

A hand-off brief for implementing Scout's collectors. Read
[collectors.md](collectors.md) first for the `core.Check` contract and a
complete worked example; this sheet says **which files to create, where, and
what goes in each**, plus the full checklist of collectors and checks to
build and the order to build them in.

---

## 1. Where collectors live

Every collector is its own package under `collectors/`:

```
collectors/
  all/all.go                 # wiring (already exists) — add one import line per collector
  internal/httpx/            # shared guarded HTTP helper (already exists) — use it
  headers/                   # <- you create these
  tls/
  exposure/
  dns/
  ports/
  nuclei/
  dast/
  auth/
  host/
  code/
  config/
```

A collector package **must** sit under `collectors/` because the HTTP helper
`collectors/internal/httpx` is an internal package only importable from there.

---

## 2. Files to create per collector

For a collector named `headers`, create **two files**, and edit **one**:

| File | Purpose |
|------|---------|
| `collectors/headers/headers.go` | The checks: `init()` registration + one `core.Check` type per check. |
| `collectors/headers/headers_test.go` | Tests driving each check against an `httptest.Server`. |
| `collectors/all/all.go` *(edit)* | Add `_ "github.com/MUKE-coder/scout/collectors/headers"` to the import block. |

Larger collectors may split checks across several files in the same package
(e.g. `headers/csp.go`, `headers/cookies.go`) — that is fine; keep one
`package headers` and one `init()` (or register in each file's `init()`).

### 2a. `collectors/<name>/<name>.go`

Must contain, for each check:

- a type implementing `core.Check` — `ID()`, `Category()`, `Mode()`,
  `Run(ctx, Target) ([]Finding, error)`;
- registration in `init()` via `core.Register(...)`;
- inside `Run`: every HTTP request through `core.HTTPClient(ctx)` (use
  `httpx.Get` / `httpx.Do`), returning `core.Finding`s with severity,
  confidence, asset, evidence, CWE/OWASP and a `core.Remediation`.

Do **not** set `Fingerprint`, `CheckID`, `Status`, `FirstSeen` or `LastSeen` —
the engine fills those. Optionally implement `Description()` (plan text) and
`OWASP()`/`ASVS()` (compliance view). Full skeleton: [collectors.md](collectors.md).

### 2b. `collectors/<name>/<name>_test.go`

One test per check, driving it with the guarded client:

```go
ctx := core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
got, err := NoSniff{}.Run(ctx, core.Target{URL: srv.URL, Environment: core.EnvDev})
```

Assert on severity, asset and remediation; cover both the "finding" and "no
finding" paths. Keep output deterministic.

### 2c. Wire it in — `collectors/all/all.go`

Add one sorted blank-import line. That is the only wiring step; the CLI
(`scout scan`/`ci`/`serve`) already imports `collectors/all`. Library users of
`scout.Mount` add the same blank import to their own program.

---

## 3. What each collector should contain

Suggested check IDs, category, and mode. **Mode is a safety contract** —
declare the most aggressive mode the check uses; the engine skips checks above
the environment cap. Start passive; only move to active/intrusive where the
probe genuinely sends attack traffic.

### `headers` — `CategoryHeaders`, **passive**
`headers.csp`, `headers.hsts`, `headers.clickjacking`, `headers.nosniff`,
`headers.referrer-policy`, `headers.permissions-policy`,
`headers.cookie-flags`, `headers.server-disclosure`. Reads one GET response
(share it via `httpx.Get`). Fixes: `remediation.SetHeader(...)`.

### `tls` — `CategoryTLS`, **passive**
`tls.weak-protocols`, `tls.weak-ciphers`, `tls.cert-expiry` (tag expired certs
with `core.TagExpiredCert`), `tls.cert-chain`, `tls.hsts-preload`. Use
`crypto/tls` via a dialer; memoize the handshake with `core.Memo`.

### `exposure` — `CategoryExposure`, **safe**
`exposure.dotenv`, `exposure.git`, `exposure.swagger`, `exposure.metrics`,
`exposure.backup-files`, `exposure.dir-listing`, `exposure.dashboards`
(including Sentinel/Pulse `/ui`). Request well-known paths and judge by status
and content type. Tag leaked secrets with `core.TagExposedSecret`.

### `dns` — `CategoryDNS`, **passive**
`dns.spf`, `dns.dkim`, `dns.dmarc`, `dns.caa`, `dns.subdomain-takeover`,
`dns.dangling-cname`. Use `net.Resolver`; these do not go through the HTTP
guard but must still respect `ctx`.

### `ports` — `CategoryNetwork`, **safe**
`network.open-ports`, `network.exposed-db`, `network.redis`,
`network.docker-api`, `network.ssh-password`. Embed `naabu` as a library, or a
bounded native TCP connect scan. Respect scope and rate limits.

### `nuclei` — `CategoryApp`, **safe/active per template**
`nuclei.<template-id>`. Embed nuclei as a library; map each result to a
`core.Finding`. Set the finding's mode from the template's classification.

### `dast` — `CategoryApp` / `CategoryAPI`
Crawler (**safe**: discover pages, forms, endpoints) then input testing.
`app.reflected-xss`, `app.open-redirect`, `app.info-disclosure` at **safe**;
`app.sqli`, `app.cmd-injection`, `app.ssrf`, `app.path-traversal`, `app.xxe`
at **active**. Active checks need the ownership-verified, opt-in path — the
engine already enforces it.

### `auth` — `CategoryAuth`, **active** (JWT inspection can be passive)
`auth.jwt-alg-none`, `auth.jwt-weak-secret`, `auth.jwt-no-expiry`,
`auth.session-fixation`, `auth.cookie-flags`, `auth.idor`,
`auth.missing-auth`, `auth.privilege-escalation`, `auth.mass-assignment`,
`auth.cors`, `auth.csrf`, `auth.rate-limit`. Use only configured **test
accounts**, never real credentials.

### `host` — `CategoryHost`, **passive** (local agent)
`host.ssh-config`, `host.firewall`, `host.listening-services`,
`host.os-cves`, `host.file-perms`, `host.env-secrets`. Runs against the local
machine, not over HTTP.

### `code` — `CategoryCode`, **passive** (operates on `Target.Repo`)
`code.govulncheck` (reachability-aware), `code.gitleaks` (repo + git history),
`code.gosec`, `code.semgrep`, `code.dockerfile`, `code.iac`. Embed each tool
as a library; emit `core.Asset{Kind: AssetFile, File, Line}` so SARIF gets
file/line.

### `config` — `CategoryConfig`, **passive**
`config.gin-debug`, `config.default-creds`, `config.sentinel-misconfig`,
`config.pulse-misconfig`, `config.inmemory-storage-prod`. Uses the route table
and in-process config exposed by `scout.Mount`.

---

## 4. Conventions (enforced by CI)

- `gofmt -l .` prints nothing; `go vet ./...` clean; `go test -race ./...`
  green; `gosec -exclude-dir=ui ./...` clean.
- Deterministic findings: no dependence on time or map iteration order.
- Stable `ID()` strings — they are part of the fingerprint; never rename a
  released check.
- One focused commit per collector, with tests, conventional message
  (`feat(headers): ...`).

## 5. Suggested build order

Native, passive, highest value first — each is self-contained and needs no
embedded engine:

1. **headers** (pure, reads one response — the template for the rest)
2. **tls**
3. **exposure**
4. **dns**
5. **config** (needs `scout.Mount` route table)

Then the heavier, dependency-embedding collectors:

6. **ports** (naabu), **nuclei**, **code** (govulncheck/gitleaks/gosec/trivy)

Then the deepest:

7. **dast** crawler + safe checks, then **auth**, then active DAST, then
   **host** agent.

> Heads-up on dependencies: the embedding collectors (nuclei, trivy, naabu,
> gosec, gitleaks, govulncheck) pull large dependency trees. Keep them in
> their own packages so a library user who only wants `Mount` plus the native
> checks is not forced to compile them; consider a build tag if the weight
> becomes a problem.

## 6. Offensive probes: implemented vs. scaffolded

The offensive collectors are wired into `collectors/all` and most probes are
implemented. The remaining scaffolds are **registered** (they appear in the
catalog and run in active scans) but their `Run` is a safe no-op marked
`TODO(you)` until you fill in the attack logic.

**Implemented (real probes):**

- **`collectors/dast`** — `app.sqli`, `app.cmd-injection`, `app.ssrf`,
  `app.path-traversal`, `app.open-redirect`, `app.reflected-xss`.
- **`collectors/authz`** — `auth.jwt`, `auth.missing`, `auth.cors`,
  `auth.idor` (needs test identities — see `scout.WithTestIdentities`).

**Scaffolded — your payload logic goes here:**

| Check | Where | Notes in the stub |
|---|---|---|
| `app.ssti` | `collectors/dast/scaffolds.go` | arithmetic marker ({{7*7}}→49), confirm server-side eval |
| `app.xxe` | `collectors/dast/scaffolds.go` | in-band entity expansion; no OOB listener yet |
| `app.file-upload` | `collectors/dast/scaffolds.go` | state-changing; needs a test identity, benign file only |
| `app.business-logic` | `collectors/dast/scaffolds.go` | state-changing; negative qty/amount against a scratch object |
| `auth.mass-assignment` | `collectors/authz/authz.go` | state-changing; submit a privileged field, read it back |

To finish one: implement the probe where marked `TODO(you)` (every request
through `core.HTTPClient(ctx)`, test accounts only, honor `Mode()`,
non-destructive), return a `core.Finding` with the ready-made
`Remediation<Name>` attached, and extend the test. Nothing else needs to
change — the check is already registered, so `scout scan` and every downstream
surface (grade, dashboard, SARIF, compliance, reports) pick it up immediately.
