---
title: Generate an SBOM
description: Emit a CycloneDX software bill of materials for a repo — with each component's known vulnerabilities, enriched with CISA KEV and FIRST EPSS, embedded inline.
---

`scout sbom` inventories a repository's dependencies across every supported
ecosystem and writes a **CycloneDX 1.6** software bill of materials. Unlike a
plain SBOM, Scout embeds the known vulnerabilities for each component —
[enriched with CISA KEV and FIRST EPSS](/usage/scan-repo/#exploitation-intelligence-kev--epss) —
so the bill of materials carries its own exploitation triage.

## Generate one

```bash
scout sbom --repo .                 # print to stdout
scout sbom --repo . -o sbom.cdx.json
scout sbom --repo . --no-vulns      # components only (no network)
```

The output validates as CycloneDX 1.6 and imports into Dependency-Track, GUAC,
`cyclonedx-cli`, and the rest of the CycloneDX ecosystem.

## What's in it

- **components** — one `library` per dependency, with its `purl`, name and
  version (npm, Go, PyPI, Maven, Composer, Cargo, RubyGems, NuGet, pub, hex).
- **vulnerabilities** — one entry per advisory affecting a component: its id,
  source, severity rating, advisory link and a fix recommendation, with
  `affects` pointing back at the component's `bom-ref`.

Scout's exploitation intelligence rides along as CycloneDX **properties** on each
vulnerability, so it survives the round-trip into other tools:

| Property | Meaning |
|---|---|
| `scout:cve` | the canonical CVE id |
| `scout:cisa-kev` | the CVE is in CISA's Known Exploited Vulnerabilities catalog |
| `scout:kev-ransomware` | known use in ransomware campaigns |
| `scout:epss` | FIRST EPSS exploitation probability (0–1) |
| `scout:epss-percentile` | EPSS percentile among all scored CVEs |

## In CI

Commit the SBOM as a build artifact, or diff it between releases to see what
changed in your dependency graph. For pass/fail gating on severity, use
[`scout ci`](/usage/ci/) instead — the SBOM is for inventory and sharing.
