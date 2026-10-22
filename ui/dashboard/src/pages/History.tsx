import { useEffect } from "react";
import { useSearchParams } from "react-router";
import { History as HistoryIcon } from "lucide-react";
import { useApi } from "../lib/useApi";
import type { Finding, Target } from "../lib/types";
import { dateTime } from "../lib/format";
import { Card, PageTitle, Spinner } from "../components/ui";
import { EmptyState, ErrorNote } from "../components/EmptyState";
import { SeverityDot, gradeVar } from "../components/Severity";

interface ScanMeta {
  id: string;
  target: Target;
  mode: string;
  started_at: string;
  grade: string;
  score: number;
}

interface DiffResponse {
  from: ScanMeta;
  to: ScanMeta;
  same_target: boolean;
  diff: { new: Finding[] | null; regressed: Finding[] | null; fixed: Finding[] | null; unchanged: Finding[] | null };
}

export function History() {
  const { data, error, loading } = useApi<{ scans: ScanMeta[] }>("/scans?limit=200");
  const [params, setParams] = useSearchParams();
  const scans = data?.scans ?? [];
  const from = params.get("from");
  const to = params.get("to");

  // Default to the latest two scans of the first target.
  useEffect(() => {
    if (from || to || scans.length < 2) return;
    const name = scans[0].target.name;
    const same = scans.filter((s) => s.target.name === name);
    if (same.length >= 2) setParams({ from: same[1].id, to: same[0].id }, { replace: true });
  }, [scans, from, to, setParams]);

  // The first click picks one scan; the second picks the other (the API
  // orders them old -> new); a click with both chosen starts over.
  function pick(id: string) {
    if (to && !from && id !== to) setParams({ from: id, to });
    else setParams({ to: id });
  }

  if (loading && !data) return <Spinner />;
  if (error) return <ErrorNote message={error} />;

  return (
    <>
      <PageTitle>History</PageTitle>
      {scans.length < 2 ? (
        <EmptyState icon={HistoryIcon}>Compare scans once there are at least two.</EmptyState>
      ) : (
        <div className="grid gap-4 xl:grid-cols-[380px_1fr]">
          <Card className="p-2">
            <p className="px-3 pt-2 pb-3 text-[12px] text-subtle">Select two scans to compare.</p>
            <ul className="max-h-[calc(100vh-260px)] overflow-y-auto">
              {scans.map((s) => {
                const role = s.id === from ? "From" : s.id === to ? "To" : null;
                return (
                  <li key={s.id}>
                    <button
                      type="button"
                      onClick={() => pick(s.id)}
                      aria-pressed={role !== null}
                      className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left transition-colors duration-150 ${
                        role ? "bg-accent-subtle" : "hover:bg-surface-2"
                      }`}
                    >
                      <span className="w-6 text-[15px] font-semibold" style={{ color: gradeVar(s.grade) }}>
                        {s.grade || "–"}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[14px]">{s.target.name}</span>
                        <span className="tabular block text-[12px] text-subtle">{dateTime(s.started_at)} · {s.mode}</span>
                      </span>
                      {role && <span className="text-[12px] font-medium text-muted">{role}</span>}
                    </button>
                  </li>
                );
              })}
            </ul>
          </Card>
          {from && to ? <DiffView from={from} to={to} /> : <EmptyState icon={HistoryIcon}>Pick a second scan.</EmptyState>}
        </div>
      )}
    </>
  );
}

function DiffView({ from, to }: { from: string; to: string }) {
  const { data, error, loading } = useApi<DiffResponse>(`/diff?from=${from}&to=${to}`);
  if (error) return <ErrorNote message={error} />;
  if (loading || !data) return <Spinner />;
  const d = data.diff;
  const counts: [string, number][] = [
    ["New", d.new?.length ?? 0],
    ["Regressed", d.regressed?.length ?? 0],
    ["Fixed", d.fixed?.length ?? 0],
    ["Unchanged", d.unchanged?.length ?? 0],
  ];
  return (
    <div className="flex flex-col gap-4">
      <Card>
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="text-[16px] font-medium">
            {data.from.target.name} · {dateTime(data.from.started_at)} → {dateTime(data.to.started_at)}
          </h2>
          <span className="tabular text-[13px] text-muted">
            <span style={{ color: gradeVar(data.from.grade) }}>{data.from.grade || "–"}</span> →{" "}
            <span style={{ color: gradeVar(data.to.grade) }}>{data.to.grade || "–"}</span>
          </span>
        </div>
        {!data.same_target && <p className="mt-2 text-[13px] text-medium-fg">These scans are of different targets.</p>}
        <dl className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
          {counts.map(([label, n]) => (
            <div key={label}>
              <dt className="text-[12px] text-subtle">{label}</dt>
              <dd className="tabular text-[22px] font-semibold">{n}</dd>
            </div>
          ))}
        </dl>
      </Card>
      <DiffSection title="New" findings={d.new} />
      <DiffSection title="Regressed" findings={d.regressed} />
      <DiffSection title="Fixed" findings={d.fixed} />
    </div>
  );
}

function DiffSection({ title, findings }: { title: string; findings: Finding[] | null }) {
  if (!findings?.length) return null;
  return (
    <Card className="p-0">
      <h3 className="border-b border-border px-6 py-4 text-[16px] font-medium">
        {title} <span className="tabular text-muted">({findings.length})</span>
      </h3>
      <ul>
        {findings.map((f) => (
          <li key={f.fingerprint} className="flex h-12 items-center gap-3 border-b border-border px-6 last:border-0">
            <SeverityDot severity={f.severity} />
            <span className="min-w-0 flex-1 truncate text-[14px]">{f.title}</span>
            <span className="hidden max-w-[40%] truncate font-mono text-[12px] text-muted sm:block">{f.asset.value}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}
