# Scout — build phases

Build Scout in order. Each phase ends with something runnable and demoable. **Do not start a phase until the previous one runs.** Mark a task `[x]` only when it is implemented, compiles, and has at least one passing test (where testable).

Convention: `[ ]` = todo, `[~]` = in progress, `[x]` = done.

---

## Phase 0 — Foundation & scaffolding
Goal: the skeleton compiles, the Mount pattern and CLI shell exist, nothing scans yet.

- [x] Initialize Go module `github.com/MUKE-coder/scout`, Go 1.24+, no CGo.
- [x] Repo layout: `core/`, `collectors/`, `engine/`, `scoring/`, `remediation/`, `storage/`, `api/`, `cli/`, `ui/`, `examples/`, `docs/`.
- [x] Define `core` types: `Finding`, `Asset`, `Evidence`, `Remediation`, `Severity`, `Confidence`, `Category`, `Mode`, `Status`, `Target`, `ScanResult`.
- [x] Define the `Check` interface and a `Registry` that checks register into.
- [x] `scout.Config` + functional options (`WithTarget`, `WithMode`, `WithScope`, `WithConfig`).
- [x] `storage` interface with two backends: in-memory ring buffer + pure-Go SQLite (`glebarez/sqlite`), auto-migrated schema.
- [x] CLI shell with `cobra`: `scan`, `serve`, `ci`, `diff`, `version` (stubs that parse flags).
- [x] `scout.Mount(router, cfg)` stub that registers the `/scout` route group.
- [x] Structured logging, graceful shutdown (`context.Context` + `sync.WaitGroup`), `scout.Version`.
- [x] CI: GitHub Actions — build, `go vet`, `gosec`, unit tests.

## Phase 1 — Engine, modes & safety core
Goal: the scan loop runs checks safely with mode caps. This is the backbone everything hangs off.

- [x] Scan engine: worker pool, context cancellation, per-check timeout, panic recovery per check (one check can never crash a scan).
- [x] **Mode enforcement**: environment (`dev|staging|prod`) → `MaxMode`; engine skips any check whose `Mode()` exceeds it.
- [x] Scope allowlist (hosts/paths), rate limiter, scan window, global kill switch.
- [x] **Dry-run / plan mode**: print which checks would run at which mode against which targets, and run nothing.
- [x] Signed self-test header (`X-Scout-Scan: <hmac>`) on all outbound scan requests.
- [x] **Target ownership verification**: DNS TXT record or `/.well-known/scout-verify.txt`; required before Active mode on any non-local host.
- [x] Findings pipeline: dedupe by fingerprint, merge FirstSeen/LastSeen, persist, emit to event bus.
- [x] Unit tests for mode capping, scope enforcement, fingerprint stability.

## Phase 2 — MVP collectors (passive + safe, any target)
Goal: point Scout at any URL and get real findings. No app integration needed yet.

- [ ] **External/TLS collector**: TLS versions, ciphers, cert expiry/chain, HSTS.
- [ ] **Headers collector**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie flags.
- [ ] **Exposure collector**: `.env`, `.git/`, `/swagger`, `/metrics`, backup files, unprotected dashboards, directory listing.
- [ ] **Port collector**: embed `naabu`; flag exposed DB/Redis/Docker/SSH-password.
- [ ] **DNS/email collector**: subdomain takeover, dangling CNAME, CAA, SPF/DKIM/DMARC.
- [ ] **Nuclei collector**: embed nuclei as a library; map templated results → `Finding`.
- [ ] Each check includes a deterministic remediation template.

## Phase 3 — Scoring, ranking & recommendations
> Started before Phase 2 finished (agreed with the owner): the Phase 2 collectors are still open. Scoring is tested with fixture findings.
Goal: findings become a grade and a prioritized to-do list.

- [x] Risk weight per finding (`severity × confidence × exposure × asset_criticality`).
- [x] Per-category score via exponential decay; overall weighted score.
- [x] Hard caps (confirmed critical → F; high internet-facing → C; expired cert / exposed secret → D).
- [x] Letter grades (A/B/C/D/F) + per-category subscores.
- [x] **"Fix next" ranking**: `points_regained_if_fixed / effort`.
- [x] Remediation renderer: what/why + stack-specific how + effort + CWE/OWASP refs.
- [x] Per-asset criticality config.
- [x] Golden-file tests pinning scores for known finding sets.

## Phase 4 — CLI output & CI mode
Goal: usable from a terminal and a pipeline before the UI exists.

- [x] `scout scan` renders a clean terminal report: grade, subscores, Fix-next top 5, findings table.
- [x] Output formats: pretty, `--json`, `--sarif` (GitHub Code Scanning).
- [x] `scout ci --fail-on <sev> --new-only`: exit codes drive build pass/fail; `--new-only` uses fingerprint diff vs. last scan.
- [x] `scout diff <a> <b>`: new / fixed / regressed.
- [x] Config file (`scout.yaml`) + env var overrides.

## Phase 5 — Dashboard (embedded React)
Goal: the product people see. Follow `style-guide.md` exactly.

- [x] `ui/dashboard` scaffold: React 19 + Vite + Tailwind 4 + Recharts + Geist. Commit `ui/dist/`, embed via `//go:embed`.
- [x] JWT auth; default creds refused outside dev; login rate limit.
- [x] REST API under `/scout/api/` + WebSocket `/scout/ws/live`.
- [x] **Overview**: grade ring, 30-day trend, category subscore bars, Fix-next top 5, env cards (dev/staging/prod).
- [x] **Findings**: filterable table (severity, category, asset, status, new/regressed), bulk actions.
- [x] **Finding detail**: request/response evidence viewer with payload highlighted, remediation panel, Verify-fix button, history timeline.
- [x] **Live scan view**: per-collector progress over WebSocket.
- [x] **Settings**: targets, scope, modes, schedules, data export (JSON/CSV), danger zone.

## Phase 6 — DAST & the Gin-aware SDK
Goal: deep app testing, with the route-table advantage.

- [ ] Crawler: spider pages, **discover and parse forms** (fields, methods, hidden inputs, CSRF tokens), discover API endpoints.
- [ ] Safe-mode DAST: reflection canaries (XSS), GET-only fuzzing, open-redirect, info disclosure.
- [ ] Active-mode DAST (dev/opt-in): SQLi, command injection, SSRF, path traversal, XXE.
- [ ] Auth checks: JWT (`alg:none`, weak secret, no-expiry), session fixation, cookie flags, password-reset flaws.
- [ ] Access-control checks: IDOR with test accounts, missing-auth, privilege escalation, mass assignment, CORS/CSRF.
- [ ] **`scout.Mount()` SDK**: export the Gin route table + middleware chain; flag unprotected routes pre-request; in-process config checks (debug mode, default creds, exposed dashboards).
- [ ] GraphQL introspection & depth; file-upload handling.

## Phase 7 — Host & code collectors
Goal: cover the server and the supply chain.

- [ ] **Host agent** (optional): SSH config, firewall, listening services, OS package CVEs, file permissions, env/process secrets.
- [ ] **Docker**: root/privileged containers, exposed socket, image CVEs (Trivy).
- [ ] **Code collector**: `govulncheck` (reachability-aware), `gitleaks` (repo + git history), `gosec` + Semgrep SAST, Dockerfile/IaC (Trivy).
- [ ] Config-posture checks consolidated (gin.DebugMode in prod, default creds, Sentinel/Pulse misconfig).

## Phase 8 — Scheduling & prod operations
Goal: safe to leave running against production.

- [x] Scheduled scans (cron) with per-schedule mode caps.
- [x] Alerting: Slack, Discord, email, webhooks (HMAC) — reuse Pulse/Sentinel patterns.
- [x] Scan history retention + pruning.
- [x] Baseline / accepted-risk workflow (mute a finding with a reason + expiry).

## Phase 9 — Sentinel & Pulse integrations
Goal: the family moat.

- [ ] **WAF effectiveness test**: safe attack corpus → Sentinel blocked vs. passed → catch-rate % + bypass list.
- [ ] **Pulse overlay**: register scans via `/pulse/api/test-runs`.
- [ ] **Shared security score**: feed Scout exposure score into Sentinel's runtime score.
- [ ] All integrations auto-detected and optional.

## Phase 10 — Advanced visualization & reporting
Goal: the "wow" surfaces.

- [x] **Attack-surface map**: interactive graph domain → hosts → ports/services → routes, nodes colored by worst severity.
- [x] **Scan diff view** in the dashboard.
- [x] **Compliance view**: OWASP Top 10 / ASVS coverage heatmap.
- [x] **Reports**: PDF/HTML export for clients/audits.
- [ ] Optional AI: explain-in-context, draft fix PR, stakeholder summary (with redaction).

## Phase 11 — Docs, examples & release
- [ ] `examples/`: minimal website scan, full Gin app with `Mount()`, CI workflow.
- [ ] Docs site (match the family docs style).
- [ ] README with badges, quick start, dashboard screenshots.
- [ ] SemVer, CHANGELOG, `STABILITY.md`, security policy, v1.0.0 tag.
