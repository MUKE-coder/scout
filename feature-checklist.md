# Scout — feature checklist

Run this checklist before calling any milestone "done". It is the acceptance gate: every box must be true, or the item is incomplete. Group by area. Don't check a box you haven't verified by actually running Scout.

---

## A. Core & safety (non-negotiable)
- [x] Every check declares a `Mode` and a `Category`.
- [x] Environment (`dev|staging|prod`) caps the max mode; checks above the cap are skipped and reported as skipped.
- [ ] A scan never sends attack traffic in Passive mode.
- [x] Prod never runs Intrusive mode; Active in prod requires explicit per-target opt-in.
- [x] Ownership verification (DNS TXT or `/.well-known/scout-verify.txt`) is enforced before Active mode on any non-local host.
- [x] Scope allowlist, rate limiting, scan windows, and a kill switch all work and are tested.
- [x] Every outbound scan request carries the signed self-test header.
- [x] Dry-run/plan mode lists exactly what would run and runs nothing.
- [x] A single failing/panicking check cannot crash the scan.
- [ ] No real user credentials are ever used; only configured test accounts.

## B. Website / black-box scanning (works with only a URL)
- [ ] Scanning an arbitrary website needs nothing installed on the target.
- [ ] Crawler discovers pages and **forms** (fields, method, hidden inputs, CSRF token presence).
- [ ] Each discovered form input is tested (per the active mode).
- [ ] API endpoints are discovered and tested.
- [ ] TLS: protocol versions, weak ciphers, cert expiry, chain, HSTS.
- [ ] Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- [ ] Cookie flags: HttpOnly, Secure, SameSite.
- [ ] Exposed files/paths: `.env`, `.git/`, `/swagger`, `/metrics`, backups, directory listing.
- [ ] Open ports & risky services (DB, Redis, Docker API, SSH password auth).
- [ ] DNS: subdomain takeover, dangling CNAME, CAA.
- [ ] Email: SPF, DKIM, DMARC.
- [ ] Nuclei templated checks run and normalize into `Finding`.

## C. App & API depth (DAST)
- [ ] SQLi, XSS (reflected/stored/DOM), command injection, SSRF, path traversal, XXE, open redirect.
- [ ] IDOR with test accounts (user A cannot reach user B's resource → or it's flagged).
- [ ] Missing-auth and privilege-escalation checks.
- [ ] JWT weaknesses: `alg:none`, weak/empty secret, missing expiry, unverified signature.
- [ ] Session fixation, password-reset flaws, MFA bypass.
- [ ] Mass assignment (`role:admin` injection).
- [ ] CORS misconfiguration and CSRF on state-changing forms.
- [ ] Rate-limit checks on login/OTP/expensive endpoints.
- [ ] Information disclosure: verbose errors, stack traces, debug endpoints.
- [ ] GraphQL introspection + depth; file-upload handling.

## D. Gin-aware SDK (white-box)
- [ ] `scout.Mount(router, cfg)` works with one line.
- [ ] Real route table + method + middleware chain is exported to the scanner.
- [ ] Unprotected/unauthenticated routes are flagged **before** any request is sent.
- [ ] In-process config checks: gin.DebugMode in prod, default creds, exposed dashboards (incl. Sentinel/Pulse `/ui`).
- [ ] A self-test endpoint lets Sentinel recognize Scout traffic.

## E. Host & supply chain
- [ ] Host agent: SSH config, firewall, listening services, OS package CVEs, file permissions, env/process secrets.
- [ ] Docker: root/privileged containers, exposed socket, image CVEs.
- [ ] Dependency CVEs via govulncheck (reachability-aware).
- [ ] Secret scanning across repo + git history.
- [ ] SAST (gosec + Semgrep rules).
- [ ] Dockerfile / IaC misconfig checks.

## F. Findings model
- [ ] Every collector emits the same `Finding` shape.
- [x] Stable fingerprint → dedupe across scans.
- [x] FirstSeen/LastSeen tracked; status lifecycle (open/fixed/accepted-risk/false-positive).
- [ ] Evidence captured (request/response, matched pattern, config line) and redactable.
- [ ] CWE + OWASP mapping on every finding.

## G. Scoring & ranking
- [x] 0–100 score + letter grade (A–F).
- [x] Per-category subscores.
- [x] Exponential decay (many lows never outweigh one critical; score never negative).
- [x] Hard caps applied (critical→F, high internet-facing→C, expired cert/exposed secret→D).
- [x] Per-asset criticality is configurable and affects the score.
- [x] "Fix next" ranking = points regained / effort, and it's sorted correctly.
- [x] Scores are deterministic and covered by golden-file tests.

## H. Recommendations
- [ ] Every check ships a deterministic remediation template (no AI required).
- [ ] Fixes are stack-specific (Gin / Nginx / Caddy / Next.js / Dockerfile as detected).
- [ ] Sentinel-aware fixes include exact config blocks.
- [ ] Each finding has a working "Verify fix" that re-runs just that check.
- [ ] Optional AI explanations redact bodies/params/PII before sending.

## I. Interfaces
- [x] `scout scan` (URL and/or repo) with mode selection.
- [x] `scout ci --fail-on --new-only --sarif` with correct exit codes.
- [x] `scout diff <a> <b>` shows new/fixed/regressed.
- [x] `scout serve` runs the dashboard.
- [x] Output formats: pretty, JSON, SARIF.
- [x] Config file + env overrides.

## J. Dashboard (see style-guide.md)
- [x] Embedded via `//go:embed`; no separate frontend deploy; `ui/dist/` committed.
- [x] JWT auth; default creds refused outside dev; login rate limit.
- [ ] Overview: grade ring, trend, subscores, Fix-next top 5, env cards.
- [ ] Findings table: filter by severity/category/asset/status/new-regressed + bulk actions.
- [ ] Finding detail slide-over: evidence viewer, remediation, verify button, history.
- [ ] Live scan view over WebSocket with per-collector progress.
- [ ] Attack-surface map (domain → host → ports → routes), colored by severity.
- [ ] Scan diff view; compliance heatmap; PDF/HTML + SARIF export.
- [ ] Looks like the Vercel/Linear aesthetic: Geist, flat, spaced, grayscale + severity color only.
- [ ] Works in both dark and light mode.

## K. Integrations (optional, auto-detected)
- [ ] Sentinel WAF effectiveness test → catch-rate % + bypass list.
- [ ] Pulse overlay via `/pulse/api/test-runs`.
- [ ] Shared security score feed into Sentinel.
- [ ] Scout is fully functional with neither Sentinel nor Pulse present.

## L. Operations & quality
- [x] Scheduled scans with per-schedule mode caps.
- [x] Alerting: Slack, Discord, email, webhook (HMAC).
- [x] Retention + pruning of scan history.
- [x] Accepted-risk/mute workflow with reason + expiry.
- [x] No CGo; builds on Linux/macOS/Windows.
- [ ] Graceful shutdown stops all goroutines.
- [ ] Unit + integration tests green in CI; gosec clean.
- [ ] Docs, examples (website scan, Gin Mount, CI workflow), README with screenshots.
- [ ] MIT license, SemVer, CHANGELOG, security policy.
