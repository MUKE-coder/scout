---
title: Checks catalog
description: Every check Scout can run, grouped by category, with the mode it belongs to and what it detects.
---

Scout's findings come from **checks** (collectors). Each belongs to a category and
a [mode](/start/modes/). This is the catalog as of the current release; run
`scout scan --dry-run` to see exactly which ones apply to a given target.

## Headers (passive)

| Check | Detects |
|---|---|
| `headers.csp` | Missing or weak Content-Security-Policy |
| `headers.hsts` | Missing HTTP Strict-Transport-Security |
| `headers.clickjacking` | Missing X-Frame-Options / frame-ancestors |
| `headers.nosniff` | Missing X-Content-Type-Options: nosniff |
| `headers.referrer-policy` | Missing / leaky Referrer-Policy |
| `headers.permissions-policy` | Missing Permissions-Policy |
| `headers.cookie-flags` | Cookies without HttpOnly / Secure / SameSite |
| `headers.server-disclosure` | Server/version banners in headers |

## TLS (passive)

| Check | Detects |
|---|---|
| `tls.cert-expiry` | Certificate expired or expiring soon |
| `tls.cert-chain` | Broken or untrusted certificate chain |
| `tls.weak-protocols` | SSLv3 / TLS 1.0 / 1.1 enabled |
| `tls.weak-ciphers` | Weak cipher suites offered |
| `tls.hsts-preload` | Not eligible for HSTS preload |

## Exposure (safe)

| Check | Detects |
|---|---|
| `exposure.dotenv` | Exposed `.env` / `.env.bak` |
| `exposure.git` | Exposed `.git/` metadata |
| `exposure.backup-files` | Reachable backup / dump files |
| `exposure.swagger` | Publicly exposed API docs |
| `exposure.metrics` | Exposed metrics endpoint |
| `exposure.dashboards` | Exposed admin dashboards |
| `exposure.dir-listing` | Autoindex directory listings |

## DNS & email (passive)

| Check | Detects |
|---|---|
| `dns.spf` | Missing / weak SPF |
| `dns.dkim` | Missing DKIM |
| `dns.dmarc` | Missing / weak DMARC |
| `dns.caa` | Missing CAA record |
| `dns.dangling-cname` | Dangling CNAME |
| `dns.subdomain-takeover` | Subdomain takeover risk |

## Network (safe)

| Check | Detects |
|---|---|
| `network.exposed-services` | Unexpected open ports / services |

## Application (safe & active)

| Check | Mode | Detects |
|---|---|---|
| `app.info-disclosure` | safe | Stack traces / verbose errors |
| `app.host-header` | safe | Host-header injection |
| `app.version-disclosure` | safe | Software/version banners |
| `app.framework-exposure` | safe | Framework-specific exposure, gated by the detected stack: Spring Boot actuators, WordPress REST user-enumeration & XML-RPC, Laravel Telescope/Ignition |
| `app.directory-listing` | safe | Directory autoindex |
| `app.missing-sri` | safe | Cross-origin script/style without SRI |
| `app.vulnerable-js-lib` | safe | Known-vulnerable client-side library (jQuery, Bootstrap, Angular…) loaded by the page, via OSV + KEV/EPSS |
| `app.php-runtime-rce` | safe | Outdated PHP runtime vulnerable to php2shell (CVE-2026-109618 / 109619), from the Server/X-Powered-By header or a Dockerfile base image |
| `app.template` | safe | A declarative YAML [detection template](/usage/templates/) matched — exposed panel, misconfiguration or CVE signature (Nuclei-compatible subset) |
| `app.mixed-content` | safe | HTTPS page loading HTTP resources |
| `app.csrf-form` | safe | State-changing form with no CSRF token |
| `app.open-redirect` | active | Open redirect |
| `app.reflected-xss` | active | Reflected XSS |
| `app.sqli` | active | SQL injection |
| `app.cmd-injection` | active | OS command injection |
| `app.ssrf` | active | Reflected SSRF (cloud-metadata response reflected back) |
| `app.blind-ssrf` | active | Blind SSRF, confirmed [out-of-band](/usage/oob/) via Scout's own OAST listener |
| `app.path-traversal` | active | Path traversal |
| `app.ssti` | active | Template injection *(scaffold)* |
| `app.xxe` | active | XML external entity *(scaffold)* |
| `app.file-upload` | active | Unrestricted upload *(scaffold)* |
| `app.business-logic` | active | Business-logic abuse *(scaffold)* |

## API (safe)

| Check | Detects |
|---|---|
| `api.graphql-introspection` | GraphQL introspection enabled |
| `api.improper-asset-mgmt` | Deprecated API version still live |

## Auth (passive, safe & active)

| Check | Mode | Detects |
|---|---|---|
| `auth.jwt` | passive | `alg:none`, unsigned or never-expiring JWT |
| `auth.cors` | safe | Permissive CORS (reflected origin + credentials) |
| `auth.missing` | active | Sensitive route reachable without auth |
| `auth.idor` | active | Broken object-level authorization (needs [test identities](/usage/idor/)) |
| `auth.mass-assignment` | active | Extra privileged fields accepted *(scaffold)* |

## Code & supply chain (`--repo`)

| Check | Detects |
|---|---|
| `code.secrets` | Hard-coded secrets in the repo |
| `code.dockerfile` | Insecure Dockerfile (root, unpinned, baked secrets) |
| `code.weak-crypto` | MD5 / SHA-1 / DES / RC4 |
| `code.insecure-random` | Insecure RNG for tokens |
| `code.dangerous-sink` | `eval` / `exec` / unsafe deserialization / raw HTML |
| `code.secret-logging` | Secrets written to logs |
| `code.unpinned-deps` | Loose dependency version ranges |
| `code.vulnerable-deps` | Known-vulnerable deps (OSV), enriched with CISA KEV + FIRST EPSS |
| `code.go-vulncheck` | Reachable Go CVEs (via `govulncheck`) |

## Configuration (passive)

| Check | Detects |
|---|---|
| `config.default-creds` | Default dashboard credentials outside dev |
| `config.gin-debug` | Gin running in debug mode |
| `config.inmemory-storage-prod` | In-memory storage in production |
| `config.sentinel-misconfig` | Misconfigured Sentinel integration |
| `config.pulse-misconfig` | Misconfigured Pulse integration |

:::note
Checks marked *(scaffold)* are registered and run in active scans but report
nothing until their probe logic is implemented — Scout ships no attack payloads.
:::
