import type { ReactNode } from "react";
import { Lightbulb } from "lucide-react";

// A one-line, data-driven "what to do next" callout shown at the top of a page.
// Scout is a diagnostic tool, so every page says how to act on what it shows.
export function Recommendation({ children, tone = "info" }: { children: ReactNode; tone?: "ok" | "warn" | "info" }) {
  const accent = tone === "ok" ? "var(--ok)" : tone === "warn" ? "var(--sev-high)" : "var(--accent)";
  return (
    <div
      className="mb-6 flex items-start gap-3 border-l-2 px-4 py-3"
      style={{ borderLeftColor: accent, backgroundColor: `color-mix(in srgb, ${accent} 6%, var(--surface))` }}
      role="note"
    >
      <Lightbulb size={16} strokeWidth={2} className="mt-0.5 shrink-0" style={{ color: accent }} aria-hidden />
      <div className="min-w-0">
        <span
          className="mb-0.5 block text-[10px] font-semibold uppercase tracking-[0.08em]"
          style={{ color: accent }}
        >
          Recommendation
        </span>
        <p className="text-[13px] leading-relaxed text-text">{children}</p>
      </div>
    </div>
  );
}
