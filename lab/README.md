# Scout Vuln Lab

> ⚠️ **INTENTIONALLY VULNERABLE.** This app ships real security holes on purpose,
> for learning (learn by exploiting) and as a test target for the **Scout**
> scanner. Run it on **localhost only**. **Never deploy it, never expose it to a
> network, and never put real data in it.**

A small Next.js app in the spirit of DVWA / OWASP Juice Shop. Every "lab" is a
working vulnerability you can exploit in the browser, and the whole app is a
fixture that exercises Scout's collectors.

## Run

```bash
cd lab
npm install
npm run dev        # http://localhost:4000
```

Open http://localhost:4000 and click a lab.

## Scan it with Scout

From the Scout repo root, with the lab running:

```bash
# black-box scan of the running app (active mode is fine on localhost/dev)
go run ./cmd/scout scan --target http://localhost:4000 --mode active --env dev

# source scan: committed secrets (.env) and the insecure Dockerfile
go run ./cmd/scout scan --repo ./lab --mode safe --env dev
```

## What's in here (and which Scout check catches it)

| Lab / artifact | Vulnerability | Scout check |
|---|---|---|
| (whole app) | No CSP / HSTS / X-Frame-Options / nosniff / Referrer / Permissions-Policy | `headers.*` |
| `session`, `lab_csrf` cookies | No HttpOnly / Secure / SameSite | `headers.cookie-flags` |
| `/.env`, `/.env.bak` | Exposed env file | `exposure.dotenv` |
| `/.git/config` | Exposed git metadata | `exposure.git` |
| `/metrics` | Exposed metrics | `exposure.metrics` |
| `/swagger.json` | Exposed API docs | `exposure.swagger` |
| `/backup.sql` | Exposed backup | `exposure.backup-files` |
| `/admin` | Unauthenticated admin area | broken access control (interactive) |
| `/search?q=` | Reflected XSS (unescaped) | `app.reflected-xss` |
| `/transfer` | State-changing form, no CSRF token | `app.csrf-form` |
| `/api/redirect?url=` | Open redirect | `app.open-redirect` |
| `/api/data` | CORS reflects Origin + credentials | `auth.cors` |
| `session` cookie | Forgeable JWT (`alg:none`, no expiry) | `auth.jwt` |
| `/api/users/[id]` | IDOR (no ownership check) | interactive (needs test accounts to auto-detect) |
| `.env` (committed) | Hard-coded secrets | `code.secrets` (`--repo`) |
| `Dockerfile` | Root user, unpinned base, secret in ENV | `code.dockerfile` (`--repo`) |
| `lib/crypto.js` | MD5/SHA-1 hashing, `Math.random` tokens | `code.weak-crypto`, `code.insecure-random` (`--repo`) |
| `lib/logger.js` | Password/token written to logs | `code.secret-logging` (`--repo`) |
| `/search`, dangerous sinks | `eval` / `exec` / raw HTML in source | `code.dangerous-sink` (`--repo`) |
| `/api/debug` | Stack trace returned to client | `app.info-disclosure` |
| `/api/graphql` | Introspection enabled | `api.graphql-introspection` |
| `/api/v1/users` + `/api/v2/users` | Deprecated API version still live | `api.improper-asset-mgmt` |
| `/api/reset` | Reset link built from the Host header | `app.host-header` |

### Also present as targets (detected once you implement the active probe)

These endpoints are deliberately vulnerable so the active DAST/auth probes
have something to hit. Scout ships the check *scaffold* for several of these
(`collectors/dast`, `collectors/authz`); the attack logic is yours to write
(see `docs/collector-buildsheet.md`).

| Endpoint | Vulnerability | Active check |
|---|---|---|
| `/api/users/[id]` | IDOR / BOLA | `auth.idor` |
| `/api/ssti?name=` | Server-side template injection | (SSTI probe) |
| `/api/ping?host=` | OS command injection | `app.cmd-injection` |
| `/api/xxe` (POST XML) | XXE | (XXE probe) |
| `/api/upload` (POST) | Unrestricted file upload | (upload probe) |
| `/api/profile` (POST) | Mass assignment (`isAdmin`) | `auth.mass-assignment` |
| `/api/checkout` (POST) | Business logic (negative quantity) | (logic probe) |
| `/api/transfer` (POST) | CSRF (no token) | `app.csrf-form` |
| `/api/data` | CORS (reflected origin + credentials) | `auth.cors` |

## Fixing them

Each lab page explains the fix. In short: parameterize/encode untrusted input,
set security headers and cookie flags, authenticate and authorize every
sensitive route and object, add CSRF tokens (or SameSite + origin checks),
allowlist redirect and CORS origins, sign and expire JWTs, and keep secrets
out of the repo and image.
