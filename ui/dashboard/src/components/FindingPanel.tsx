import { useEffect, useState } from "react";
import { Check, Copy, RotateCw, X } from "lucide-react";
import { useApi } from "../lib/useApi";
import { api, ApiError } from "../lib/api";
import type { Fix, FindingRow, HistoryEntry, Status } from "../lib/types";
import { STATUSES } from "../lib/types";
import { capitalize, categoryLabel, dateTime, effortLabel, statusLabel } from "../lib/format";
import { Button, Spinner } from "./ui";
import { ErrorNote } from "./EmptyState";
import { Pill, SeverityBadge, SeverityDot } from "./Severity";

interface Detail {
  finding: FindingRow;
  history: HistoryEntry[];
}

// Slide-over with a finding's evidence, fix and history (style guide §5:
// the table row opens this instead of navigating away).
export function FindingPanel({ fingerprint, onClose, onChanged }: { fingerprint: string; onClose: () => void; onChanged: () => void }) {
  const { data, error, loading, reload } = useApi<Detail>(`/findings/${encodeURIComponent(fingerprint)}`);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(true));
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", esc);
    return () => {
      cancelAnimationFrame(id);
      document.removeEventListener("keydown", esc);
    };
  }, [onClose]);

  const refresh = () => {
    reload();
    onChanged();
  };

  return (
    <div className="fixed inset-0 z-30 flex justify-end" role="dialog" aria-modal="true" aria-label="Finding detail">
      <div className={`absolute inset-0 bg-black/40 transition-opacity duration-200 ${shown ? "opacity-100" : "opacity-0"}`} onClick={onClose} />
      <aside
        className={`relative flex h-full w-full max-w-2xl flex-col border-l border-border bg-bg transition-transform duration-200 ease-out ${
          shown ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <div className="flex h-14 shrink-0 items-center justify-between border-b border-border px-6">
          <span className="text-[13px] font-medium text-muted">Finding</span>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close">
            <X size={16} strokeWidth={1.5} />
          </Button>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-6">
          {error ? <ErrorNote message={error} /> : loading && !data ? <Spinner /> : data && <Body detail={data} onChanged={refresh} />}
        </div>
      </aside>
    </div>
  );
}

function Body({ detail, onChanged }: { detail: Detail; onChanged: () => void }) {
  const f = detail.finding;
  const r = f.remediation;
  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.severity} />
          <Pill className="bg-surface-2 text-muted">{capitalize(f.confidence)}</Pill>
          <Pill className="bg-surface-2 text-muted">{categoryLabel(f.category)}</Pill>
          {f.change && f.change !== "unchanged" && <Pill className="bg-accent-subtle text-text">{capitalize(f.change)}</Pill>}
        </div>
        <h2 className="text-[22px] leading-snug font-semibold">{f.title}</h2>
        <div className="font-mono text-[13px] break-all text-muted">
          {f.asset.value}
          {f.location && ` (${f.location})`}
        </div>
        <div className="text-[12px] text-subtle">
          {f.target} · first seen {dateTime(f.first_seen)} · last seen {dateTime(f.last_seen)} · <span className="font-mono">{f.check_id}</span>
        </div>
        <Actions f={f} onChanged={onChanged} />
      </header>

      {(r.what || r.why) && (
        <Section title="What and why">
          {r.what && <p>{r.what}</p>}
          {r.why && <p className="mt-2 text-muted">{r.why}</p>}
        </Section>
      )}

      {r.how && r.how.length > 0 && (
        <Section title="How to fix" aside={`Effort: ${effortLabel[r.effort] ?? "Medium"}`}>
          <Fixes fixes={r.how} />
        </Section>
      )}

      <EvidenceSection f={f} />

      {((f.cwe?.length ?? 0) > 0 || (f.owasp?.length ?? 0) > 0 || (r.references?.length ?? 0) > 0) && (
        <Section title="References">
          <ul className="flex flex-col gap-1 text-[13px]">
            {f.cwe?.map((c) => (
              <li key={c}>
                <a className="text-muted underline-offset-2 hover:text-text hover:underline" href={`https://cwe.mitre.org/data/definitions/${c.replace("CWE-", "")}.html`} target="_blank" rel="noreferrer">
                  {c}
                </a>
              </li>
            ))}
            {f.owasp?.map((o) => (
              <li key={o} className="text-muted">
                OWASP {o}
              </li>
            ))}
            {r.references?.map((ref) => (
              <li key={ref}>
                <a className="break-all text-muted underline-offset-2 hover:text-text hover:underline" href={ref} target="_blank" rel="noreferrer">
                  {ref}
                </a>
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section title="History">
        <ol className="flex flex-col">
          {detail.history.map((h) => (
            <li key={h.scan_id} className="flex items-center gap-3 border-b border-border py-2 text-[13px] last:border-0">
              <SeverityDot severity={h.severity} />
              <span className="tabular w-40 text-muted">{dateTime(h.at)}</span>
              <span>{statusLabel(h.status)}</span>
              <span className="ml-auto font-mono text-[12px] text-subtle">{h.scan_id.slice(0, 12)}</span>
            </li>
          ))}
        </ol>
      </Section>
    </div>
  );
}

function Actions({ f, onChanged }: { f: FindingRow; onChanged: () => void }) {
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  async function verify() {
    setVerifying(true);
    setResult(null);
    try {
      const res = await api<{ fixed: boolean; error?: string }>(`/findings/${encodeURIComponent(f.fingerprint)}/verify`, { method: "POST" });
      setResult(res.error ? `Check failed: ${res.error}` : res.fixed ? "Fixed: the issue is gone." : "Still present.");
      if (res.fixed) onChanged();
    } catch (e) {
      setResult(e instanceof ApiError ? e.message : "Could not run the check.");
    } finally {
      setVerifying(false);
    }
  }

  async function setStatus(status: Status) {
    try {
      await api("/findings/status", { method: "POST", body: JSON.stringify({ fingerprints: [f.fingerprint], status }) });
      onChanged();
    } catch (e) {
      setResult(e instanceof ApiError ? e.message : "Could not update the status.");
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button variant="primary" onClick={verify} disabled={verifying}>
        {verifying ? <Spinner size={14} /> : <RotateCw size={16} strokeWidth={1.5} aria-hidden />}
        Verify fix
      </Button>
      <select
        aria-label="Status"
        value={f.status}
        onChange={(e) => setStatus(e.target.value as Status)}
        className="h-9 rounded-lg border border-border bg-bg px-3 text-[13px]"
      >
        {STATUSES.map((s) => (
          <option key={s} value={s}>
            {statusLabel(s)}
          </option>
        ))}
      </select>
      {result && (
        <span role="status" className="text-[13px] text-muted">
          {result}
        </span>
      )}
    </div>
  );
}

function Section({ title, aside, children }: { title: string; aside?: string; children: React.ReactNode }) {
  return (
    <section>
      <div className="mb-3 flex items-baseline justify-between">
        <h3 className="text-[16px] font-medium">{title}</h3>
        {aside && <span className="text-[12px] text-subtle">{aside}</span>}
      </div>
      {children}
    </section>
  );
}

const stackLabels: Record<string, string> = { gin: "Gin", nginx: "Nginx", caddy: "Caddy", nextjs: "Next.js", dockerfile: "Dockerfile", sentinel: "Sentinel", generic: "Any stack" };

function Fixes({ fixes }: { fixes: Fix[] }) {
  const [active, setActive] = useState(0);
  const fix = fixes[Math.min(active, fixes.length - 1)];
  return (
    <div>
      {fixes.length > 1 && (
        <div role="tablist" className="mb-3 flex flex-wrap gap-1">
          {fixes.map((fx, i) => (
            <button
              key={`${fx.stack}-${i}`}
              role="tab"
              type="button"
              aria-selected={i === active}
              onClick={() => setActive(i)}
              className={`h-8 rounded-lg px-3 text-[13px] font-medium transition-colors duration-150 ${
                i === active ? "bg-surface-2 text-text" : "text-muted hover:text-text"
              }`}
            >
              {stackLabels[fx.stack] ?? fx.stack}
            </button>
          ))}
        </div>
      )}
      <CodeBlock code={fix.code} />
      {fix.note && <p className="mt-2 text-[13px] text-muted">{fix.note}</p>}
    </div>
  );
}

function EvidenceSection({ f }: { f: FindingRow }) {
  const e = f.evidence;
  const blocks = [
    { label: "Request", text: e.request },
    { label: "Response", text: e.response },
    { label: "Config", text: e.config_line },
  ].filter((b) => b.text);
  if (blocks.length === 0 && !e.matched && !e.notes) return null;
  return (
    <Section title="Evidence" aside={e.redacted ? "Redacted" : undefined}>
      <div className="flex flex-col gap-3">
        {e.matched && blocks.length === 0 && <CodeBlock code={e.matched} highlight={e.matched} />}
        {blocks.map((b) => (
          <div key={b.label}>
            <div className="mb-1 text-[12px] text-subtle">{b.label}</div>
            <CodeBlock code={b.text!} highlight={e.matched} />
          </div>
        ))}
        {e.notes && <p className="text-[13px] text-muted">{e.notes}</p>}
      </div>
    </Section>
  );
}

// Evidence / code viewer (style guide §5): Geist Mono 13px on surface-2,
// matched payload highlighted with the accent tint, ghost copy button.
function CodeBlock({ code, highlight }: { code: string; highlight?: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <div className="relative">
      <pre className="max-h-96 overflow-auto rounded-lg border border-border bg-surface-2 p-4 pr-12 font-mono text-[13px] leading-relaxed whitespace-pre-wrap break-all">
        {highlight ? highlightText(code, highlight) : code}
      </pre>
      <Button variant="ghost" size="sm" onClick={copy} aria-label="Copy" className="absolute top-2 right-2">
        {copied ? <Check size={16} strokeWidth={1.5} /> : <Copy size={16} strokeWidth={1.5} />}
      </Button>
    </div>
  );
}

function highlightText(text: string, needle: string) {
  if (!needle || needle.length < 2) return text;
  const parts = text.split(needle);
  if (parts.length === 1) return text;
  return parts.flatMap((p, i) =>
    i === 0
      ? [p]
      : [
          <mark key={i} className="rounded-sm bg-accent-subtle px-0.5 text-text outline outline-1 outline-accent/40">
            {needle}
          </mark>,
          p,
        ],
  );
}
