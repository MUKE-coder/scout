// Finding detail slide-over. Placeholder until the detail view lands.
export function FindingPanel({ onClose }: { fingerprint: string; onClose: () => void; onChanged: () => void }) {
  return (
    <div className="fixed inset-0 z-30 flex justify-end bg-black/40" onClick={onClose}>
      <aside className="h-full w-full max-w-xl border-l border-border bg-bg p-6" onClick={(e) => e.stopPropagation()}>
        <p className="text-muted">Finding detail is coming next.</p>
      </aside>
    </div>
  );
}
