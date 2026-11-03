---
title: Reconnaissance (WHOIS, DNS, subdomains)
description: Every URL scan now includes passive reconnaissance — WHOIS registration, DNS records and subdomains from certificate transparency — the information-gathering step of a pen test.
---

Reconnaissance is the first step of any assessment: map the target's public
footprint before you test it. When you scan a URL, Scout now gathers it
automatically and shows a **Reconnaissance** section in the report and a **Recon**
page in the dashboard — no extra flags, no extra tools.

It is **passive**: Scout queries public services (WHOIS servers, DNS, crt.sh), not
the target itself beyond ordinary DNS. It runs for a real domain and is skipped
for `localhost`, bare IPs and repo-only scans.

## What it collects

**WHOIS** — the domain registration: registrar, organization, creation and expiry
dates, name servers, status flags, and any non-abuse contact emails. (Equivalent
to `whois example.com`.)

**DNS records** — `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, and reverse `PTR` of the
primary address. (Equivalent to `dig example.com ANY` / `nslookup -type=ns`.)

**Subdomains** — discovered passively from **certificate transparency** logs
(crt.sh), the same source as `crt.sh/?q=%.example.com`. Forgotten `dev.`,
`staging.` or `shop.` hosts often surface here.

## Example

```
Reconnaissance  tesla.com
  whois       registrar MarkMonitor Inc. · created 1992-11-04 · expires 2028-11-03
  nameservers a1-12.akam.net, edns69.ultradns.com, …
  status      clientTransferProhibited, serverDeleteProhibited, …
  dns         A 23.40.100.207 · MX tesla-com.mail.protection.outlook.com · NS …
  reverse     a2-18-53-207.deploy.static.akamaitechnologies.com
  subdomains  37  dev.tesla.com, shop.tesla.com, …
```

## Why it matters

The recon section is the attacker's starting map. Review it for:

- **Unexpected subdomains** — dev/staging/admin hosts that shouldn't be public, or
  dangling records that invite subdomain takeover.
- **Infrastructure** — name servers and reverse DNS reveal the CDN/hosting and
  sometimes origin servers hidden behind it.
- **Expiry and contacts** — a near-expiry domain or an exposed registrant email is a
  phishing / social-engineering lever.

This complements Scout's **active** recon, which already runs as part of a scan:
security-header and cookie analysis, technology/framework
[stack detection](/usage/scan-repo/), exposed files and directories, and the
[attack-surface map](/usage/dashboard-tour/).
