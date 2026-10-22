# Scout — build instructions for Claude Code

You are building **Scout**, a self-hosted, open-source vulnerability scanner and attack-surface mapper for developers. Tagline: *"Point it at your app. See every way in."* It is the third tool in a family alongside **Sentinel** (runtime defense) and **Pulse** (observability), and it must feel like it belongs next to them.

## Read these first, in this order
1. **`project-description.md`** — the full vision, tech stack, architecture, findings model, scoring, and how it all fits together. This is the source of truth for *what* Scout is.
2. **`phases.md`** — the ordered build plan. You execute this phase by phase, top to bottom.
3. **`style-guide.md`** — binding visual rules for the dashboard. Follow it exactly.
4. **`feature-checklist.md`** — the acceptance gate. Nothing is "done" until its boxes are genuinely true.

## How to work
- **Build in phase order.** Start at Phase 0. Do not begin a phase until the previous one compiles, runs, and its tasks are checked off in `phases.md`.
- **Keep `phases.md` updated.** As you finish each task, change its `[ ]` to `[x]` in the file. Use `[~]` for the task you're actively on. This file is the shared progress tracker — keep it honest.
- **One phase = one runnable milestone.** At the end of every phase, there must be something I can run and see (a CLI command, a test, a screen). Tell me the exact command.
- **Verify against `feature-checklist.md`** at the end of each relevant phase. Only check a box after you've actually run the thing and confirmed it.
- **Safety is not optional.** The dev/prod mode system, scope allowlist, ownership verification, and the signed self-test header (Phase 1) must exist before any Active-mode check is written. Never ship a check that can run destructively against production by default.

## Non-negotiable constraints (from the vision)
- **Go 1.24+, no CGo.** Pure-Go SQLite (`glebarez/sqlite`). Gin + GORM.
- **Embed engines as libraries** (nuclei, trivy, govulncheck, gitleaks, naabu, gosec) and normalize their output into the single `Finding` type. Write native Go checks only where nothing good exists (Gin route analysis, auth logic, form testing, Sentinel/Pulse config validation).
- **One unified findings model, one scoring system, one dashboard.** The orchestration layer is the product — not any single engine.
- **Self-hosted, open source (MIT).** No hosted SaaS, no multi-tenant, no telemetry.
- **Go + Gin first.** The external and code collectors work for any target; broader framework support is explicitly future work.
- **It must scan an arbitrary website from just a URL** — crawling pages and forms — and report all vulnerabilities, with no app integration required. The Gin SDK (`scout.Mount`) is an enrichment, never a prerequisite.
- **Embedded React dashboard** (React 19 + Vite + Tailwind 4 + Recharts + **Geist** font) via `//go:embed`, with `ui/dist/` committed so consumers need no Node. Match `style-guide.md`: Vercel/Linear look, flat, grayscale base, severity color only, generous spacing.

## Conventions to mirror from Sentinel & Pulse
- Single `Mount()` entry point; functional-options config plus a `Config` struct.
- JWT (HS256) dashboard auth; default credentials refused outside dev mode; login rate limit.
- URL namespacing: dashboard at `/scout/ui/`, API at `/scout/api/`, WebSocket at `/scout/ws/live`.
- In-memory ring buffers on the hot path + SQLite for persistence; retention + pruning.
- Graceful shutdown via `context.Context` + `sync.WaitGroup`.
- Deterministic, reviewable behavior over magic; AI features are optional and redacted.

## Before you start coding
1. Confirm you've read all four companion files and restate, in 3–4 bullets, what Scout is and the phase you're about to start.
2. Propose the concrete repo/package layout for Phase 0 and the core type definitions (`Finding`, `Check`, `Mode`, `Category`, etc.) for my quick review.
3. Then begin Phase 0. After each phase, stop, show me what runs, update `phases.md`, and wait for a go-ahead before the next phase.

## Definition of done (whole project)
Every box in `feature-checklist.md` is true, Scout scans both a local Gin app and an arbitrary website safely, every finding has a stack-specific fix and a one-click re-verify, and the dashboard looks like it belongs next to Pulse and Sentinel.

Start by reading the files and confirming the plan.
