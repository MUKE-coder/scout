---
name: scout
description: >-
  Run a security scan with Scout and act on the results. Use when the user wants
  to scan or audit an app, website, repository or network for vulnerabilities;
  asks "is my app/site secure?", "scan this repo", "check my dependencies",
  "find exposed services", "generate an SBOM", "any secrets committed?"; or wants
  to fix, triage or re-check security findings. Scout is a self-hosted scanner:
  black-box DAST, attack-surface mapping, dependency/SCA (with KEV+EPSS), SAST,
  secrets, supply-chain, LLM-app checks, and CIDR network sweeps.
---

# Scout security scanning

Scout is a single Go binary. This skill runs it correctly for the situation and
turns its output into fixes. Scout is **detective** — it does not run destructive
exploits — and it caps what it does by scan mode and environment, so default runs
are safe.

## 1. Make sure Scout is installed

Run `scout version`. If it is missing, install it (it self-updates afterwards):

- **macOS / Linux:** `curl -fsSL https://scout.codetotech.com/install.sh | sh`
- **Windows (PowerShell):** `irm https://scout.codetotech.com/install.ps1 | iex`
- **With Go:** `go install github.com/MUKE-coder/scout/cmd/scout@latest`

## 2. Pick the right scan

| The user has… | Run |
|---|---|
| a running web app / site | `scout scan --target <url>` |
| a local source repo | `scout scan --repo .` |
| a public GitHub repo (no checkout) | `scout scan --repo https://github.com/owner/repo` |
| both the app and its source | `scout scan --target <url> --repo .` |
| a LAN / subnet (authorized) | `scout scan --network 192.168.1.0/24` |
| just a bill of materials | `scout sbom --repo .` |

Useful flags:

- `--serve` — after the scan, open the dashboard (grade, findings, attack-surface
  map, remediation). Great for a human to explore.
- `--json` — machine-readable output; prefer this when you (the agent) will parse
  results. `--sarif <file>` for GitHub Code Scanning.
- `--mode active --env dev` — on a **local/dev** app, run the active probes
  (reflected + blind SSRF/XSS/SQLi/command injection via an out-of-band listener).
  Safe mode is the default and needs no opt-in.

## 3. Read the results

- **Grade A–F** is the headline; it is **capped** by the worst finding (a confirmed
  critical caps the whole scan at F), so fix the caps first.
- **Fix next** ranks findings by points regained ÷ effort — work top-down.
- **Severity** (critical→info) and **confidence** (confirmed / likely / possible).
  Prefer confirmed.
- **`[Exploited]` / CISA KEV** means the CVE is being exploited in the wild — do
  these first. **EPSS** is the probability it will be. Both ride on dependency and
  client-library findings.
- Each finding carries **what / why / how** remediation plus CWE and OWASP tags.

## 4. Fix and re-check

1. Take the top **Fix next** item. Read its remediation (`what`/`why`/`how`).
2. Apply the fix in the code or config.
3. Re-scan the same target. The finding should drop out (or flip to *fixed* in the
   dashboard/history). Re-run until the grade stops improving.

For a machine loop, scan with `--json`, fix, and compare: `scout diff` and
`scout ci --fail-on high` give pass/fail and new/fixed/regressed deltas.

## 5. Safety and authorization — do not skip

- **Modes** escalate `passive < safe < active < intrusive` and are **capped by
  environment** (`dev` allows all, `staging`/`prod` cap lower). Active/intrusive
  against a **non-local** host needs proven ownership (`scout ownership <url>`)
  and `--allow-active`.
- **Only scan targets you own or are explicitly authorized to test.** A network
  sweep (`--network`) of anything but your own LAN needs written authorization —
  say so to the user before running it.
- Default `scout scan --target <url>` (safe mode) is non-destructive: no payloads,
  just benign requests.

## Common one-liners

```bash
scout scan --target http://localhost:3000 --mode active --env dev   # deep local app scan
scout scan --repo . --sbom sbom.cdx.json                            # source scan + SBOM
scout scan --repo https://github.com/owner/repo                     # clone & scan a repo
scout scan --network 192.168.1.0/24                                 # sweep your LAN (authorized)
scout scan --target https://example.com --serve                     # scan, then open the dashboard
scout ci --repo . --fail-on high                                    # gate a CI pipeline
```
