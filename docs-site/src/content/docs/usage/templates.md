---
title: Detection templates
description: Scout runs declarative YAML detection templates (a safe, Nuclei-compatible subset), so new CVE, exposed-panel and misconfiguration checks are data you can add without recompiling.
---

Scout ships a template engine (`app.template`) that runs **declarative YAML
detection templates** against a live target. Detections become *data*: a new
exposed-panel, misconfiguration or known-CVE signature is a YAML file, not Go
code — and you can drop your own in without rebuilding Scout.

The format is a **safe subset of [Nuclei](https://github.com/projectdiscovery/nuclei)**
templates, so many existing community templates work as-is.

## Running them

Built-in templates run automatically in any safe-mode scan. Point Scout at a
directory of your own with `--templates` (or the `SCOUT_TEMPLATES` env var):

```bash
scout scan --target https://example.com --templates ./my-templates
```

## Writing one

```yaml
id: apache-server-status

info:
  name: Apache mod_status (/server-status) is publicly exposed
  severity: medium          # critical | high | medium | low | info
  description: mod_status discloses active requests, client IPs and server internals.
  remediation: Restrict /server-status to localhost, or disable mod_status.
  reference:
    - https://httpd.apache.org/docs/current/mod/mod_status.html
  classification:
    cwe-id: CWE-200
    owasp: A05:2021

http:
  - method: GET
    path:
      - "{{BaseURL}}/server-status"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body            # body | header | all
        words: ["Apache Server Status", "Scoreboard"]
        condition: and        # and | or
```

Supported matchers: `status`, `word`, `regex`, each with `part`
(`body`/`header`/`all`), `condition` (`and`/`or`), and `negative`. Combine
matchers with `matchers-condition`. `{{BaseURL}}` and `{{Hostname}}` are
substituted.

## Safety

Scout stays **detective, never weaponized**. The engine runs only `GET`/`HEAD`
requests with no body. Templates that use raw requests, request bodies, fuzzing
payloads, or variable/interpolation expressions in the path (anything beyond
`{{BaseURL}}`/`{{Hostname}}`) are **skipped** — Scout will not fire an exploit
from a template. The subset is for *detection* (exposed panels, version/CVE
signatures, misconfigurations), not active exploitation; for active probes use
[`--mode active`](/start/modes/).
