import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

// Empty state (style guide §5): outline icon, one muted line, one action.
export function EmptyState({ icon: Icon, children, action }: { icon: LucideIcon; children: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-4 rounded-xl border border-border bg-surface px-6 py-16 text-center">
      <Icon size={24} strokeWidth={1.5} className="text-subtle" aria-hidden />
      <p className="max-w-md text-muted">{children}</p>
      {action}
    </div>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <div role="alert" className="rounded-xl border border-critical/40 bg-surface px-6 py-4 text-[13px] text-critical-fg">
      {message}
    </div>
  );
}
