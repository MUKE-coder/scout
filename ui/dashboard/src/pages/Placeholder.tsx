import { Construction } from "lucide-react";

// Temporary page until each screen lands.
export function Placeholder({ title }: { title: string }) {
  return (
    <div>
      <h1 className="text-[28px] font-semibold tracking-[-0.02em]">{title}</h1>
      <div className="mt-8 flex flex-col items-center gap-3 rounded-xl border border-border bg-surface px-6 py-16 text-center">
        <Construction size={24} strokeWidth={1.5} className="text-subtle" aria-hidden />
        <p className="text-muted">This screen is being built.</p>
      </div>
    </div>
  );
}
