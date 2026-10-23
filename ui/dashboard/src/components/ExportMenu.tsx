import { useEffect, useRef, useState } from "react";
import { Download } from "lucide-react";
import { download, ApiError } from "../lib/api";
import { Button } from "./ui";

// Export menu: download the latest findings in a developer-friendly format
// (hand the Markdown/HTML to an engineer to fix the vulnerabilities).
const FORMATS: { id: string; label: string; hint: string }[] = [
  { id: "md", label: "Markdown (.md)", hint: "Findings + fixes, for a PR or ticket" },
  { id: "html", label: "HTML (.html)", hint: "Printable, self-contained report" },
  { id: "txt", label: "Plain text (.txt)", hint: "Paste into an email or chat" },
  { id: "json", label: "JSON (.json)", hint: "Machine-readable" },
  { id: "csv", label: "CSV (.csv)", hint: "Spreadsheet" },
];

export function ExportMenu() {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", esc);
    };
  }, [open]);

  async function pick(format: string) {
    setError(null);
    setBusy(format);
    const stamp = new Date().toISOString().slice(0, 10);
    try {
      await download(`/export?format=${format}`, `scout-report-${stamp}.${format}`);
      setOpen(false);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Export failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div ref={ref} className="relative">
      <Button variant="secondary" onClick={() => setOpen((o) => !o)} aria-haspopup="menu" aria-expanded={open}>
        <Download size={16} strokeWidth={1.5} aria-hidden />
        Export
      </Button>
      {open && (
        <div role="menu" className="absolute right-0 z-20 mt-2 w-72 rounded-xl border border-border bg-surface p-2 shadow-lg">
          <p className="px-3 pb-1 pt-1 text-[11px] font-medium uppercase tracking-wide text-muted">Export findings</p>
          {FORMATS.map((f) => (
            <button
              key={f.id}
              role="menuitem"
              type="button"
              disabled={busy !== null}
              onClick={() => pick(f.id)}
              className="flex w-full flex-col items-start rounded-lg px-3 py-2 text-left transition-colors duration-150 hover:bg-surface-2 disabled:opacity-50"
            >
              <span className="text-[14px] font-medium">
                {f.label}
                {busy === f.id && <span className="ml-2 text-muted">…</span>}
              </span>
              <span className="text-[12px] text-muted">{f.hint}</span>
            </button>
          ))}
          {error && <p className="px-3 py-2 text-[13px] text-critical-fg">{error}</p>}
        </div>
      )}
    </div>
  );
}
