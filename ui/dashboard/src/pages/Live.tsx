import { useState } from "react";
import { Activity, OctagonX, Play } from "lucide-react";
import { useLive } from "../lib/live";
import { api, ApiError } from "../lib/api";
import type { ScanProgress } from "../lib/types";
import { ago, categoryLabel } from "../lib/format";
import { Button, Card, PageTitle, Spinner } from "../components/ui";
import { EmptyState, ErrorNote } from "../components/EmptyState";

export function Live() {
  const { scans, connected, killed, refresh } = useLive();
  const [error, setError] = useState<string | null>(null);

  async function toggleKill() {
    setError(null);
    try {
      await api(killed ? "/resume" : "/kill", { method: "POST" });
      refresh();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach Scout.");
    }
  }

  return (
    <>
      <PageTitle
        action={
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-2 text-[12px] text-muted">
              <span className={`size-2 rounded-full ${connected ? "bg-ok" : "bg-info"}`} aria-hidden />
              {connected ? "Live" : "Reconnecting…"}
            </span>
            <Button variant={killed ? "secondary" : "danger"} onClick={toggleKill}>
              {killed ? <Play size={16} strokeWidth={1.5} aria-hidden /> : <OctagonX size={16} strokeWidth={1.5} aria-hidden />}
              {killed ? "Resume scanning" : "Kill switch"}
            </Button>
          </div>
        }
      >
        Live scan
      </PageTitle>

      {error && <div className="mb-4"><ErrorNote message={error} /></div>}
      {killed && (
        <div className="mb-4 rounded-xl border border-critical/40 bg-surface px-6 py-4 text-[13px] text-critical-fg">
          The kill switch is engaged: no scan requests are sent until you resume.
        </div>
      )}

      {scans.length === 0 ? (
        <EmptyState icon={Activity}>No scans have run since Scout started. Start one with New scan.</EmptyState>
      ) : (
        <div className="flex flex-col gap-4">
          {scans.map((s) => (
            <ScanCard key={s.id} scan={s} />
          ))}
        </div>
      )}
    </>
  );
}

// Per-collector progress: checks grouped by the prefix of their ID.
function collectors(s: ScanProgress) {
  const groups = new Map<string, { checks: number; findings: number; errors: number }>();
  for (const c of s.checks ?? []) {
    const key = c.id.split(".")[0] || c.id;
    const g = groups.get(key) ?? { checks: 0, findings: 0, errors: 0 };
    g.checks++;
    g.findings += c.findings;
    if (c.error) g.errors++;
    groups.set(key, g);
  }
  return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));
}

function ScanCard({ scan }: { scan: ScanProgress }) {
  const pct = scan.total > 0 ? (scan.done / scan.total) * 100 : scan.finished ? 100 : 0;
  const active = !scan.finished;
  return (
    <Card>
      <div className="mb-4 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          {active ? <Spinner /> : <span className={`size-2 rounded-full ${scan.error ? "bg-critical" : "bg-ok"}`} aria-hidden />}
          <span className="font-mono text-[13px]">{scan.id.slice(0, 12)}</span>
          <span className="text-[12px] text-subtle">started {ago(scan.started)}</span>
        </div>
        <span className="tabular text-[13px] text-muted">
          {scan.done}/{scan.total} checks · {scan.findings} findings
        </span>
      </div>
      <Bar pct={pct} />
      {scan.error && <p className="mt-3 text-[13px] text-critical-fg">{scan.error}</p>}
      {collectors(scan).length > 0 && (
        <ul className="mt-4 flex flex-col">
          {collectors(scan).map(([name, g]) => (
            <li key={name} className="flex items-center gap-3 border-b border-border py-2 text-[13px] last:border-0">
              <span className="w-28">{categoryLabel(name)}</span>
              <span className="tabular text-muted">{g.checks} checks</span>
              {g.errors > 0 && <span className="text-critical-fg">{g.errors} failed</span>}
              <span className="tabular ml-auto text-muted">{g.findings} findings</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

// Thin progress bar: 2px track, accent fill. Calm, not a casino.
function Bar({ pct }: { pct: number }) {
  return (
    <div className="h-0.5 overflow-hidden rounded-full bg-border" role="progressbar" aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100}>
      <div className="h-full rounded-full bg-accent transition-[width] duration-200 ease-out" style={{ width: `${pct}%` }} />
    </div>
  );
}
