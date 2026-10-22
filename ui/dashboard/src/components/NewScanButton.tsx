import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { Play } from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { Target } from "../lib/types";
import { Button } from "./ui";

// "New scan" (top bar): pick a configured target, start a scan, go to Live.
export function NewScanButton({ targets }: { targets: Target[] }) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

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

  async function start(t: Target) {
    setError(null);
    try {
      await api<{ id: string }>("/scans", { method: "POST", body: JSON.stringify({ target: t.name }) });
      setOpen(false);
      navigate("/live");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start the scan.");
    }
  }

  return (
    <div ref={ref} className="relative">
      <Button variant="primary" onClick={() => setOpen((o) => !o)} aria-haspopup="menu" aria-expanded={open}>
        <Play size={16} strokeWidth={1.5} aria-hidden />
        New scan
      </Button>
      {open && (
        <div role="menu" className="absolute right-0 z-20 mt-2 w-72 rounded-xl border border-border bg-surface p-2">
          {targets.length === 0 ? (
            <p className="px-3 py-2 text-[13px] text-muted">Add targets to scout.yaml to scan them from here.</p>
          ) : (
            targets.map((t) => (
              <button
                key={t.name}
                role="menuitem"
                type="button"
                onClick={() => start(t)}
                className="flex w-full flex-col items-start rounded-lg px-3 py-2 text-left transition-colors duration-150 hover:bg-surface-2"
              >
                <span className="text-[14px] font-medium">{t.name}</span>
                <span className="font-mono text-[12px] text-muted">{t.url || t.repo}</span>
              </button>
            ))
          )}
          {error && <p className="px-3 py-2 text-[13px] text-critical-fg">{error}</p>}
        </div>
      )}
    </div>
  );
}
