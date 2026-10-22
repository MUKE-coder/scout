import type { ReactNode } from "react";
import type { Severity } from "../lib/types";
import { capitalize } from "../lib/format";

// Severity color appears only as small dots, left accents and badge text,
// never as large filled blocks (style guide §3).
const dot: Record<Severity, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  info: "bg-info",
};

const badge: Record<Severity, string> = {
  critical: "bg-critical/12 text-critical-fg",
  high: "bg-high/12 text-high-fg",
  medium: "bg-medium/12 text-medium-fg",
  low: "bg-low/12 text-low-fg",
  info: "bg-info/12 text-info-fg",
};

export function SeverityDot({ severity }: { severity: Severity }) {
  return <span aria-hidden className={`inline-block size-2 shrink-0 rounded-full ${dot[severity]}`} />;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Pill className={badge[severity]}>{capitalize(severity)}</Pill>;
}

export function Pill({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <span className={`inline-flex h-[22px] shrink-0 items-center rounded-md px-2 text-[12px] font-medium whitespace-nowrap ${className}`}>
      {children}
    </span>
  );
}

// Stroke/fill colors for SVG and charts, as CSS variables.
export const severityVar: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

// Grade colors run ok → medium → critical from A to F.
export function gradeVar(grade: string): string {
  switch (grade) {
    case "A":
    case "B":
      return "var(--ok)";
    case "C":
      return "var(--sev-medium)";
    case "D":
      return "var(--sev-high)";
    case "F":
      return "var(--sev-critical)";
  }
  return "var(--text-subtle)";
}
