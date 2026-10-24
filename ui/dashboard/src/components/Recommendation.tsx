import type { ReactNode } from "react";
import { Lightbulb } from "lucide-react";

// A one-line, data-driven "what to do next" callout shown at the top of a page.
// Scout is a diagnostic tool, so every page says how to act on what it shows.
export function Recommendation({ children, tone = "info" }: { children: ReactNode; tone?: "ok" | "warn" | "info" }) {
  const accent = tone === "ok" ? "var(--ok)" : tone === "warn" ? "var(--sev-high)" : "var(--accent)";
  return (
    <div
      className="mb-6 flex items-start gap-3 rounded-xl border border-border bg-surface px-4 py-3"
      style={{ borderLeft: `3px solid ${accent}` }}
      role="note"
    >
      <Lightbulb size={18} strokeWidth={1.8} className="mt-0.5 shrink-0" style={{ color: accent }} aria-hidden />
      <p className="text-[13px] leading-relaxed text-muted">
        <span className="font-medium text-text">Recommendation: </span>
        {children}
      </p>
    </div>
  );
}
