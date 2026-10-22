import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../lib/api";
import type { Status } from "../lib/types";
import { Button, Input, Label } from "./ui";

// needsReason marks statuses that record a decision someone must justify.
export const needsReason = (s: Status) => s === "accepted-risk" || s === "false-positive";

// StatusDialog asks why a risk is accepted (and until when) or why a finding
// is a false positive, then applies the status to the given fingerprints.
export function StatusDialog({
  status,
  fingerprints,
  onDone,
  onCancel,
}: {
  status: Status;
  fingerprints: string[];
  onDone: () => void;
  onCancel: () => void;
}) {
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const accepting = status === "accepted-risk";
  const tomorrow = new Date(Date.now() + 864e5).toISOString().slice(0, 10);

  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onCancel();
    document.addEventListener("keydown", esc);
    return () => document.removeEventListener("keydown", esc);
  }, [onCancel]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/findings/status", {
        method: "POST",
        body: JSON.stringify({ fingerprints, status, reason, until: accepting ? until : "" }),
      });
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not update findings.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center px-4" role="dialog" aria-modal="true" aria-label={accepting ? "Accept risk" : "Mark false positive"}>
      <div className="absolute inset-0 bg-black/40" onClick={onCancel} />
      <form onSubmit={submit} className="relative w-full max-w-md rounded-xl border border-border bg-surface p-6">
        <h2 className="text-[18px] font-semibold">{accepting ? "Accept risk" : "Mark as false positive"}</h2>
        <p className="mt-1 text-[13px] text-muted">
          {fingerprints.length} finding{fingerprints.length > 1 ? "s" : ""}.{" "}
          {accepting ? "It stops counting toward the grade until it expires." : "It stops counting toward the grade."}
        </p>
        <div className="mt-6 flex flex-col gap-4">
          <div>
            <Label htmlFor="reason">Reason</Label>
            <Input id="reason" autoFocus required value={reason} onChange={(e) => setReason(e.target.value)} placeholder={accepting ? "Only reachable from the office VPN" : "The flagged value is a public test key"} />
          </div>
          {accepting && (
            <div>
              <Label htmlFor="until">Expires (optional)</Label>
              <Input id="until" type="date" min={tomorrow} value={until} onChange={(e) => setUntil(e.target.value)} />
              <p className="mt-1 text-[12px] text-subtle">When it expires, the finding counts again and reopens on the next scan.</p>
            </div>
          )}
          {error && <p role="alert" className="text-[13px] text-critical-fg">{error}</p>}
          <div className="mt-2 flex justify-end gap-2">
            <Button variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" disabled={busy || !reason.trim()}>
              {accepting ? "Accept risk" : "Mark false positive"}
            </Button>
          </div>
        </div>
      </form>
    </div>
  );
}
