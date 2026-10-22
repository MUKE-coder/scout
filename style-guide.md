# Scout — style guide

The dashboard must look like it belongs next to a Vercel or Linear product: **clean, flat, linear, generously spaced, quietly confident**. No gradients-as-decoration, no heavy shadows, no neon. Information density with calm. If a screen feels busy, remove, don't rearrange.

This guide is binding for the embedded React dashboard (`ui/dashboard`) and any marketing/docs surface.

---

## 1. Principles
- **Flat & linear.** Flat surfaces, hairline borders, lots of whitespace. Depth comes from spacing and subtle borders, not shadows.
- **Monochrome base, color only for meaning.** The UI is near-grayscale. Color appears only to signal severity, status, or a single accent action.
- **Content first.** Chrome recedes. The grade, the findings, and the fixes are the stars.
- **Consistent rhythm.** One spacing scale, one type scale, one radius. Everything snaps to an 8px grid (4px for fine adjustments).
- **Fast & legible.** Real data, no skeleton-forever. Tables are scannable; numbers are tabular.

---

## 2. Typography

- **Font family:** **Geist** (sans) for all UI text; **Geist Mono** for code, payloads, hashes, ports, file paths, and any evidence. Load via self-hosted woff2 (don't depend on a CDN at runtime for a self-hosted tool).
- **Scale** (desktop):
  - Display / page title: 28px / 600 / tracking -0.02em
  - h1: 22px / 600
  - h2: 18px / 600
  - h3: 16px / 500
  - Body: 14px / 400 / line-height 1.6
  - Small / labels: 13px / 500
  - Caption / meta: 12px / 400
  - Mono (evidence): 13px / 400
- **Weights:** 400, 500, 600 only. Never 700+ in the UI.
- **Case:** Sentence case everywhere. No ALL CAPS except tiny uppercase eyebrow labels at 11px with +0.06em tracking, used sparingly.
- **Numbers:** use `font-variant-numeric: tabular-nums` in tables, scores, and metrics.

---

## 3. Color tokens

Define as CSS variables; ship light and dark (dark is default for a dev tool, both must work). Neutral ramp is the backbone.

### Neutrals (zinc/gray)
```
--bg            #0A0A0A   (dark page)      /  #FFFFFF (light)
--surface       #111111                    /  #FAFAFA
--surface-2     #161616                    /  #F4F4F5
--border        #262626                    /  #E4E4E7
--border-strong #343434                    /  #D4D4D8
--text          #FAFAFA                    /  #09090B
--text-muted    #A1A1AA                    /  #52525B
--text-subtle   #71717A                    /  #71717A
```

### Accent (one, and only one) — indigo/violet to tie into the family
```
--accent        #6E56CF
--accent-hover  #7C66DD
--accent-fg     #FFFFFF
--accent-subtle #6E56CF1A   (10% — backgrounds of selected rows, focus rings)
```

### Severity (the only other colors; use consistently everywhere)
```
--sev-critical  #E5484D   (red)
--sev-high      #F76B15   (orange)
--sev-medium    #F5A623   (amber)
--sev-low       #3B82F6   (blue)
--sev-info      #71717A   (gray)
--ok            #30A46C   (green — "fixed", "passed", grade A)
```

Rules:
- Severity colors appear as **small dots, left border accents, and badge text** — never as large filled blocks.
- Badges: subtle tinted background (color at ~12% alpha) + the darkest shade of the same hue for text. Never white text on a saturated fill for severity.
- Grade ring uses `--ok` → `--sev-medium` → `--sev-critical` mapped to A→F.

---

## 4. Spacing & layout

- **8px grid.** Spacing scale: 4, 8, 12, 16, 24, 32, 48, 64.
- **Page padding:** 32px desktop, 16px mobile.
- **Card padding:** 20–24px.
- **Section gap:** 32px between major sections, 16px within.
- **Max content width:** 1280px, centered, with a persistent left nav (≈240px).
- **Breathing room is the aesthetic.** When unsure, add 8px, not remove it.

### App shell
- **Left sidebar** (240px): logo wordmark "Scout" top-left, nav items with 16px icons + label, active item has `--accent-subtle` background + `--text` and a 2px left accent bar. Env switcher (dev/staging/prod) pinned at the bottom.
- **Top bar** (56px): current target selector, "New scan" primary button (right), scan status pill when a scan is live.
- **Main**: scrollable content, no nested scrollbars.

---

## 5. Components

### Cards
Flat `--surface`, 1px `--border`, `border-radius: 12px`, 20–24px padding. No shadow by default; on hover for interactive cards, `--border-strong` only (no lift, no shadow).

### Buttons
- Radius 8px, height 36px (sm 32px), 14px/500 label, 12px horizontal padding minimum.
- **Primary:** `--accent` bg, `--accent-fg` text, `--accent-hover` on hover.
- **Secondary:** transparent bg, 1px `--border`, `--text`; hover `--surface-2`.
- **Ghost:** no border, `--text-muted`; hover `--surface-2` + `--text`.
- **Danger:** `--sev-critical` text/border, tinted bg on hover. Used for destructive actions only.
- Focus: 2px ring in `--accent` at 40% alpha, 2px offset. Never remove focus rings.

### Badges / pills
Height 20–22px, radius 6px, 12px/500, tinted bg + same-hue dark text. One per concept (severity, status, new/regressed).

### Tables (findings — the core surface)
- Header row: 12px/500 `--text-muted`, uppercase-ish eyebrow optional, sticky on scroll.
- Rows: 48px tall, 1px `--border` bottom divider, hover `--surface-2`.
- First cell: severity dot + title. Mono for assets/routes.
- Right-aligned numeric columns with tabular-nums.
- Row click → side panel (slide-over) with finding detail; don't navigate away.
- Zebra striping is **off**; rely on dividers and hover.

### Grade ring (hero element on Overview)
Circular progress, 160px, 8px stroke, track in `--border`, fill mapped to grade color. Big number (48px/600) + letter grade in the center. Subscores as horizontal bars beneath, each labeled, colored by that category's worst severity.

### Charts (Recharts)
- Line/area for trends: 1.5px stroke, accent color, no fill or a 6% accent fill max, no gridline clutter (horizontal gridlines only, `--border`, dashed).
- Axis labels 12px `--text-muted`. No chart legends when one series. No 3D, no rounded bar caps beyond 2px.
- Tooltips: `--surface-2` card, 1px border, 12px text.

### Evidence / code viewer
Geist Mono, 13px, `--surface-2` bg, 1px border, radius 8px, 16px padding. Highlight the injected payload / matched pattern with `--accent-subtle` background. Copy button top-right (ghost).

### Live scan view
Per-collector rows with a thin progress bar (2px track, accent fill), a spinner only while active, and a running count of findings. Calm, not a casino.

### Empty & loading states
- Empty: centered icon (outline, 24px, `--text-subtle`), one line of `--text-muted`, one primary action. Never a blank screen.
- Loading: a single subtle top progress bar or inline spinners — no full-page skeleton shimmer that outlives the data.

---

## 6. Icons
Outline icons only (Lucide or Tabler outline), 16px inline / 20px nav / 24px decorative max. Inherit text color. Never filled variants. Icons support labels; they don't replace them in nav.

---

## 7. Motion
- Fast and subtle: 120–160ms ease-out for hovers, 200ms for slide-overs.
- Animate `opacity` and `transform` only. No layout-thrash animations.
- Respect `prefers-reduced-motion`.

---

## 8. Dark mode
Dark is the default. Every token has a light counterpart; test every screen in both. Mental test: if the background were pure black, is every text and border still legible? Borders carry the layout in dark mode — never rely on shadow.

---

## 9. Do / Don't
- **Do** align everything to the 8px grid.
- **Do** keep color meaningful — grayscale UI, colored signals.
- **Do** use mono for anything a machine produced (routes, ports, hashes, payloads).
- **Don't** use drop shadows, gradients-as-decoration, glassmorphism, or more than one accent.
- **Don't** put large saturated color blocks on screen.
- **Don't** Title Case headings or exceed weight 600.
- **Don't** nest scroll areas or let tables overflow the card.
