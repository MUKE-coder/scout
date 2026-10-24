import { useState } from "react";
import { useNavigate } from "react-router";
import { Check, Circle, Play, Copy } from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { TargetOverview, Overview } from "../lib/types";
import { Card } from "./ui";

// Scan coverage: Scout is a diagnostic tool, so we show which diagnostic
// "dimensions" a target has been scanned for, a progress bar, and the next
// scan to run (with what it diagnoses). Derived from the latest scan's mode,
// whether a repo was scanned, and how many scans exist (trend).
const RANK: Record<string, number> = { passive: 0, safe: 1, active: 2, intrusive: 3 };

interface Dim {
  key: string;
  title: string;
  diagnoses: string;
  done: boolean;
  mode?: "safe" | "active"; // triggerable from the dashboard
  cli?: string; // shown when it can't be triggered here
}

export function CoveragePanel({ current, data }: { current: TargetOverview; data: Overview }) {
  const navigate = useNavigate();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // History-exact: every mode ever run against this target, not just the latest.
  const modesRun = current.modes ?? [current.mode];
  const ranRank = Math.max(0, ...modesRun.map((m) => RANK[m] ?? 0));
  const repoScanned = data.targets.some((t) => t.target.repo);
  const hasTrend = (current.scans ?? 0) >= 2;
  const configured = (data.configured ?? []).some((t) => t.name === current.target.name);
  const host = current.target.url || current.target.name;

  const dims: Dim[] = [
    {
      key: "surface",
      title: "Surface & misconfiguration",
      diagnoses: "Security headers, TLS, exposed files, CORS and DNS/email records.",
      done: true, // a scan exists
    },
    {
      key: "active",
      title: "Injection & server-side probes",
      diagnoses: "SQL injection, XSS, open redirect, SSRF and path traversal.",
      done: ranRank >= RANK.active,
      mode: "active",
      cli: `scout scan --target ${host} --mode active --env dev`,
    },
    {
      key: "source",
      title: "Source & dependencies",
      diagnoses: "Hard-coded secrets, insecure Dockerfiles, weak crypto and reachable CVEs.",
      done: repoScanned,
      cli: "scout scan --repo .",
    },
    {
      key: "baseline",
      title: "Baseline & trend",
      diagnoses: "A second scan so regressions (new or returning findings) are caught.",
      done: hasTrend,
      mode: "safe",
      cli: `scout scan --target ${host}`,
    },
  ];

  const doneCount = dims.filter((d) => d.done).length;
  const pct = Math.round((doneCount / dims.length) * 100);

  async function run(mode: "safe" | "active") {
    setError(null);
    setBusy(mode);
    try {
      await api<{ id: string }>("/scans", { method: "POST", body: JSON.stringify({ target: current.target.name, mode }) });
      navigate("/live");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start the scan.");
    } finally {
      setBusy(null);
    }
  }

  async function copy(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      window.setTimeout(() => setCopied(null), 1500);
    } catch {
      /* ignore */
    }
  }

  return (
    <Card>
      <div className="mb-1 flex items-baseline justify-between">
        <h2 className="text-[16px] font-medium">Scan coverage</h2>
        <span className="text-[13px] text-muted">
          <span className="tabular font-medium text-text">{doneCount}</span> of {dims.length} diagnostics · {pct}%
        </span>
      </div>
      <p className="mb-3 text-[13px] text-muted">
        How thoroughly {current.target.name} has been diagnosed. Run the rest for full coverage.
      </p>
      <div className="mb-5 h-2 overflow-hidden rounded-full bg-border">
        <div className="h-full rounded-full bg-accent transition-[width] duration-500" style={{ width: `${pct}%` }} />
      </div>

      <ul className="flex flex-col gap-3">
        {dims.map((d) => (
          <li key={d.key} className="flex items-start gap-3">
            <span className="mt-0.5 shrink-0">
              {d.done ? (
                <Check size={18} strokeWidth={2.4} className="text-accent" aria-label="done" />
              ) : (
                <Circle size={18} strokeWidth={1.8} className="text-subtle" aria-label="to do" />
              )}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className={`text-[14px] font-medium ${d.done ? "" : "text-text"}`}>{d.title}</span>
                {d.done && <span className="text-[11px] font-medium text-accent">✓ done</span>}
              </div>
              <p className="mt-0.5 text-[13px] text-muted">
                <span className="text-subtle">Diagnoses:</span> {d.diagnoses}
              </p>
              {!d.done && (
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  {d.mode && configured ? (
                    <button
                      type="button"
                      onClick={() => run(d.mode!)}
                      disabled={busy !== null}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-2.5 py-1.5 text-[13px] font-medium text-accent-fg transition-[filter] hover:brightness-105 disabled:opacity-50"
                    >
                      <Play size={14} strokeWidth={2} aria-hidden />
                      {busy === d.mode ? "Starting…" : `Run ${d.mode} scan`}
                    </button>
                  ) : null}
                  {d.cli && (
                    <button
                      type="button"
                      onClick={() => copy(d.cli!, d.key)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1.5 font-mono text-[12px] text-muted transition-colors hover:border-border-strong hover:text-text"
                      title="Copy command"
                    >
                      <Copy size={13} strokeWidth={1.8} aria-hidden />
                      {copied === d.key ? "Copied" : d.cli}
                    </button>
                  )}
                </div>
              )}
            </div>
          </li>
        ))}
      </ul>
      {error && <p className="mt-3 text-[13px] text-critical-fg">{error}</p>}
    </Card>
  );
}
