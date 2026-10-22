# Scout — project description

> Point it at your app. See every way in.

Scout is a self-hosted, open-source **vulnerability scanner and attack-surface mapper** for developers. You give it a target — a running app, a website, a server, a repo — and it probes for security weaknesses, deduplicates them into a single findings model, scores the result into a letter grade, and tells you the exact fix for each issue, ranked by how much safety each fix buys per hour of work.

It is the third tool in a family:

- **Sentinel** — runtime defense (WAF, rate limiting, threat detection). *Stops attacks.*
- **Pulse** — observability (tracing, DB analysis, runtime metrics). *Shows what's happening.*
- **Scout** — offensive testing (finds vulnerabilities before attackers do). *Finds the holes.*

Scout is built to feel like one product family with Sentinel and Pulse: the same `Mount()` ergonomics, the same embedded React dashboard, the same self-hosted, zero-external-services philosophy.

---

## 1. The problem

Developers ship fast and have no cheap, trustworthy way to answer "is this safe to deploy?" The existing options are bad for an individual developer or small team:

- **Enterprise scanners** (Burp Suite Pro, Nessus, Qualys) are expensive, heavyweight, and built for security specialists, not app developers.
- **Point tools** (nmap, sqlmap, nuclei, trivy, gitleaks) are powerful but fragmented. You run five tools, get five different output formats, and have to stitch together what it means and what to do.
- **Nothing understands the app.** Black-box scanners guess at routes and have no idea which endpoints are protected. They can't tell you "this route has no auth middleware" because they can't see your code.
- **Results are noise, not action.** A wall of 400 findings with no ranking and no stack-specific fix is worse than useless — it gets ignored.

Scout's bet: **orchestration + a unified findings model + trustworthy scoring + a beautiful dashboard + stack-aware fixes** is more valuable to a developer than any single engine. And because Scout can optionally see the app's real Gin route table, it knows things a black-box scanner never can.

---

## 2. Who it's for

- A solo developer or small team shipping Go/Gin apps who wants a security check in dev and a safe, scheduled scan in prod.
- Anyone who wants to point a scanner at **any website** (not just their own Go app) and get a plain-English list of vulnerabilities — including issues in forms, headers, TLS, and exposed files.

---

## 3. What it does — the two entry points

### A. Black-box scan (any website or host)
Point Scout at a URL or IP. It needs nothing installed on the target. It crawls the site, discovers pages and **forms**, tests inputs, inspects TLS, headers, DNS, and open ports, and reports everything it finds. This is the "check a simple website and tell me all the vulnerabilities" mode.

### B. White-box / in-app scan (Go + Gin apps first)
Add one line to a Gin app:

```go
scout.Mount(router, scout.Config{ AppName: "My API" })
```

This gives Scout two things a black-box scan can't have:
1. **The real route table** — every path, method, and the middleware chain protecting it. Scout can flag "route has no auth middleware" *before* sending a request.
2. **In-process config checks** — debug mode on in prod, default credentials, Sentinel in log-only mode, in-memory storage in prod, exposed `/metrics` or dashboards.

Both entry points feed the same findings engine, scoring, and dashboard. White-box is an enrichment of black-box, never a replacement — a Scout scan always works with nothing but a URL.

---

## 4. Dev vs prod — the core safety design

The single most important design decision. The same injection payload that's fine against `localhost` can corrupt data or trip an outage in production. So **every check declares a mode**, and **every environment caps the mode it will run**.

| Mode | What it does | Dev (local) | Staging | Prod |
|---|---|---|---|---|
| **Passive** | Reads headers, TLS, DNS, config, route table. Sends no attack traffic. | ✅ | ✅ | ✅ |
| **Safe** | Harmless probes: canary strings for reflection, GET-only fuzzing, version checks, read-only auth checks. | ✅ | ✅ | ✅ (rate-limited) |
| **Active** | Real injection payloads, auth-bypass attempts, IDOR with test accounts. | ✅ | ✅ | ⚠️ opt-in per target only |
| **Intrusive** | Brute force, load/DoS-style tests, state-changing requests (POST/PUT/DELETE). | ✅ | ⚠️ opt-in | ❌ never |

### Prod guardrails (build these from day one, not later)
- **Target ownership verification** before any Active scan against a non-local host: a DNS TXT record or a `/.well-known/scout-verify.txt` file. This protects the user and prevents Scout from being pointed at someone else's site.
- **Scope allowlist** — only hosts/paths explicitly in scope are touched.
- **Rate limiting, scan windows, and a global kill switch.**
- **Signed self-test header** on every Scout request (e.g. `X-Scout-Scan: <hmac>`), so Sentinel can tag Scout traffic as a self-test rather than a real attacker.
- **Test accounts only.** Never real user credentials. No state-changing requests unless explicitly allowed per route.
- **Dry-run / plan mode** — print what *would* run at a given mode against a target before running it.

---

## 5. What it tests (collectors)

Scout organizes checks into **collectors**. Each collector is independent and emits the shared `Finding` type.

### App & API — the DAST collector (black-box + Gin-aware)
- **Crawling & form discovery** — spiders the site, finds pages, forms, inputs, and API endpoints. Parses HTML forms (fields, methods, hidden inputs, CSRF tokens) and tests each one.
- **OWASP Top 10** — SQLi, XSS (reflected/stored/DOM), command injection, SSRF, path traversal, XXE, open redirect.
- **Broken access control** — IDOR (user A fetches user B's resource by changing an ID), missing auth on routes, privilege escalation (user → admin routes), forced browsing to hidden paths.
- **Authentication** — JWT weaknesses (`alg:none`, weak/empty secret, no expiry, no signature check), session fixation, cookie flags (`HttpOnly`, `Secure`, `SameSite`), password-reset flaws, MFA bypass.
- **Rate limiting** — on login, OTP, password reset, and expensive endpoints.
- **Mass assignment** — sending `{"role":"admin"}` and seeing if it sticks.
- **CORS & CSRF** — permissive `Access-Control-Allow-Origin`, missing CSRF protection on state-changing forms.
- **Information disclosure** — verbose errors, stack traces, debug endpoints, exposed `/swagger`, `.env`, `.git/`, `/metrics`, backup files, and unprotected dashboards (including Sentinel's and Pulse's own `/ui`).
- **File upload** handling; **GraphQL** introspection and query-depth limits.

> **Gin-aware differentiator:** with `scout.Mount()`, the DAST collector reads the real route table and middleware chain. It knows every endpoint without guessing and can flag unprotected or unauthenticated routes before sending traffic.

### Edge & network — the external collector
- **Ports & services** — open ports, exposed databases, Redis, Docker API, SSH with password auth.
- **TLS** — protocol versions, weak ciphers, cert expiry, chain issues, HSTS.
- **Security headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- **DNS** — subdomain takeover, dangling CNAMEs, CAA records.
- **Email security** — SPF, DKIM, DMARC (domain spoofing exposure).
- **Exposure** — admin panels, origin-IP leaks behind a CDN.

### Server & host — the agent collector (optional, for your own servers)
- **SSH** config (root login, password auth), firewall rules, listening services.
- **OS packages** — CVEs, kernel version, unattended upgrades.
- **Docker** — containers as root, privileged mode, exposed socket, image CVEs.
- **File permissions** on `.env`, keys, and the SQLite files Sentinel/Pulse create.
- **Secrets** in environment variables and process args.

### Code & supply chain — the dev/CI collector
- **Dependency CVEs** — `govulncheck` (reachability-aware: tells you if the vulnerable function is actually called), plus `osv-scanner` for non-Go ecosystems later.
- **Secret scanning** — repo and git history (gitleaks-style rules).
- **SAST** — `gosec` + Semgrep rules: SQL string building, weak crypto, unsafe deserialization, path handling.
- **Container & IaC** — Dockerfile and config misconfigurations (Trivy).
- **Licenses** (optional).

### Configuration posture
- Debug/dev mode in production (`gin.DebugMode`).
- Default credentials anywhere.
- Sentinel/Pulse config checks (log-only WAF, in-memory storage in prod, default dashboard passwords).

---

## 6. Technical implementation

### Stack (mirrors Sentinel & Pulse deliberately)
- **Language:** Go 1.24+, no CGo.
- **Web/API:** Gin. **ORM:** GORM.
- **Storage:** pure-Go SQLite (`github.com/glebarez/sqlite`) for persistence; in-memory ring buffers for the live scan hot path. Postgres adapter later for multi-node.
- **Dashboard:** embedded React via `//go:embed` — React 19, Vite, Tailwind CSS 4, Recharts. No separate frontend deploy. `ui/dist/` is committed so consumers need no Node.
- **Auth:** JWT (HS256), same pattern as Pulse/Sentinel. Default creds refused outside dev mode.
- **Live updates:** WebSocket hub streaming scan progress and findings.
- **Config:** functional options (`scout.WithTarget(...)`, `scout.WithMode(...)`) plus a `Config` struct via `scout.WithConfig(...)`.

### Embed engines, don't reinvent them
The best open-source engines are Go libraries. Embed them as libraries (not shelled-out binaries) and normalize their output into `Finding`:
- **Nuclei** (projectdiscovery) — templated web/CVE checks.
- **Trivy** — containers, IaC, OS packages.
- **govulncheck / osv-scanner** — dependency CVEs.
- **gitleaks** — secrets.
- **naabu** — port scanning.
- **gosec** — Go SAST.

Write **native Go checks** only where nothing good exists: Gin route-table analysis, auth-logic tests (IDOR, JWT, mass assignment), form discovery/testing, Sentinel/Pulse config validation. Scout's value is the orchestration layer, the unified model, scoring, fixes, and UI — not re-implementing engines.

### The Check interface
Everything is a pluggable check:

```go
type Mode int       // Passive | Safe | Active | Intrusive
type Category int    // TLS, Headers, App, API, Auth, Network, Host, Code, Config...

type Check interface {
    ID() string              // "tls.weak-protocols", "app.sqli", "auth.jwt-alg-none"
    Category() Category
    Mode() Mode              // the most aggressive mode this check uses
    Run(ctx context.Context, t Target) ([]Finding, error)
}
```

A scan = select checks whose `Mode() <= environment.MaxMode`, run them against in-scope targets with a worker pool and context cancellation, stream findings to the hub, persist, then score.

### The findings model (the heart of the product)
Every collector outputs the same shape. This is what makes dedupe, diffs, scoring, and the dashboard possible.

```go
type Finding struct {
    Fingerprint string      // stable hash: checkID + asset + location → dedupe across scans
    CheckID     string
    Title       string
    Category    Category
    Severity    Severity    // critical | high | medium | low | info
    CVSS        float64
    Confidence  Confidence  // confirmed | likely | possible
    Asset       Asset       // domain, host:port, route, file:line, container
    Evidence    Evidence    // raw request/response, matched pattern, config line
    CWE         []string
    OWASP       []string    // "A01:2021"
    Remediation Remediation // what, why, how (stack-specific), effort, refs
    Status      Status      // open | fixed | accepted-risk | false-positive
    FirstSeen   time.Time
    LastSeen    time.Time
}
```

The **fingerprint** is the key idea: it's stable across scans, so Scout can show **new / fixed / regressed** between any two scans — the view a developer actually cares about after a deploy.

### Scoring & ranking
A **0–100 score plus a letter grade**, with per-category subscores. Modeled on SSL Labs: trusted because one serious flaw caps the grade regardless of what else is good.

Per finding, a risk weight:
```
risk = severity_base × confidence × exposure × asset_criticality

severity_base:     critical 40 · high 20 · medium 8 · low 2 · info 0
confidence:        confirmed 1.0 · likely 0.7 · possible 0.4
exposure:          internet-facing 1.0 · authenticated-only 0.6 · internal 0.4
asset_criticality: user-set per asset (payments API 1.5, marketing site 0.7)
```

Per category: `score = 100 × e^(−Σrisk / k)` — exponential decay so 30 trivial header findings never outweigh one real SQL injection, and the score never goes negative.

Overall: weighted average of categories (App/API weighted highest), then **hard caps**:
- Any confirmed critical → max grade **F**.
- Any confirmed high on an internet-facing asset → max **C**.
- Expired cert or publicly exposed secret → max **D**.

Grades: A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60.

**"Fix next" ranking:** for each open finding, `points_regained_if_fixed / effort(S|M|L)`. The top of the list is always the fix that buys the most safety per hour. (Same idea as Pulse's N+1 impact ranking.)

### Recommendations
Each check ships a **deterministic remediation template** — reliable, reviewable, free to produce (AI is optional sugar on top, never the source of truth). A remediation contains:
- **What & why** — plain language + a realistic attack scenario.
- **How to fix, specific to the detected stack** — a Gin middleware snippet, an Nginx/Caddy directive, a Next.js header config, a Dockerfile line.
- **Sentinel-aware fixes** — e.g. "Enable `AuthShield` on `/api/login`" with the exact config block.
- **Effort estimate + references** (CWE, OWASP, docs).
- **A "Verify fix" action** — re-runs just that one check against just that asset, in seconds.

Optional AI (reusing Sentinel's redaction approach: strip bodies, params, PII before anything leaves the process): explain a finding in context, draft a fix PR, or summarize a scan for a non-technical stakeholder.

---

## 7. Integration with Sentinel & Pulse (the moat)

No one else has all three pieces:
- **WAF effectiveness test** — fire a safe attack corpus at the app, measure what Sentinel blocked vs. let through → "WAF catch rate: 94%" plus the list of bypasses. Sentinel already measures WAF accuracy in CI; Scout does it against the live deployment.
- **Pulse overlay** — register each scan via Pulse's `/pulse/api/test-runs` endpoint so scans appear as bands on latency/RPS charts; see whether scanning affects performance.
- **Shared security score** — Scout's exposure score can feed Sentinel's runtime security score into one combined number: how well the app defends at runtime × how exposed it is.

These integrations are **optional and auto-detected**. Scout is fully useful with neither installed.

---

## 8. Interfaces

### CLI
```bash
# Dev: full active scan of a local app + its repo
scout scan --target http://localhost:8080 --repo . --mode active

# Any website: safe black-box scan, no install on the target
scout scan --target https://example.com --mode safe

# CI: fail the build on new high/critical findings, emit SARIF
scout ci --repo . --fail-on high --new-only --sarif out.sarif

# Server: dashboard + scheduled safe scans
scout serve   # → http://localhost:9090/ui

# Diff two scans
scout diff <scan-a> <scan-b>
```

### SDK (Go + Gin)
```go
scout.Mount(router, scout.Config{ AppName: "My API" })
// adds route discovery + in-process config checks + a self-test endpoint
```

### Dashboard — URLs mirror the family
- Dashboard: `http://localhost:9090/scout/ui/`
- API: `http://localhost:9090/scout/api/`
- WebSocket: `ws://localhost:9090/scout/ws/live?token=<jwt>`

---

## 9. Non-goals (at least for v1)
- Not a hosted SaaS — **self-hosted only**. (No multi-tenant, no scanning-as-a-service abuse surface.)
- Not a replacement for a professional penetration test — it's continuous, automated coverage between pentests.
- Not stack-agnostic yet — **Go + Gin first**; the external and code collectors already work for any app, and broader framework support comes later.
- Not closed/open-core — **fully open source**, MIT, like Sentinel and Pulse.

---

## 10. Success criteria
- A developer can scan a local Gin app **and** an arbitrary website with one command and get a grade + ranked fixes in under a minute for a safe scan.
- Every finding has a stack-specific, copy-pasteable fix and a one-click re-verify.
- Running a safe scan against production is safe by construction (mode caps + ownership verification + guardrails).
- The dashboard looks and feels like it belongs next to Pulse and Sentinel.
- Zero external services required: `go get`, one `Mount()` or one CLI command, done.
