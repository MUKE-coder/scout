import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { ListChecks, Search } from "lucide-react";
import { useApi } from "../lib/useApi";
import { api, ApiError } from "../lib/api";
import type { FindingRow, Status } from "../lib/types";
import { SEVERITIES, STATUSES } from "../lib/types";
import { capitalize, categoryLabel, statusLabel } from "../lib/format";
import { Button, Input, PageTitle, Spinner } from "../components/ui";
import { EmptyState, ErrorNote } from "../components/EmptyState";
import { Pill, SeverityDot } from "../components/Severity";
import { FindingPanel } from "../components/FindingPanel";
import { StatusDialog, needsReason } from "../components/StatusDialog";

const CATEGORIES = ["app", "api", "auth", "tls", "headers", "exposure", "network", "dns", "host", "code", "config"];
const FILTERS = ["severity", "category", "status", "change", "target", "q"] as const;

export function Findings() {
  const [params, setParams] = useSearchParams();
  const query = new URLSearchParams();
  for (const k of FILTERS) {
    const v = params.get(k);
    if (v) query.set(k, v);
  }
  const { data, error, loading, reload } = useApi<{ findings: FindingRow[] }>(`/findings?${query}`);
  const targets = useApi<{ findings: FindingRow[] }>("/findings").data;
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkError, setBulkError] = useState<string | null>(null);
  const [dialog, setDialog] = useState<Status | null>(null);

  const rows = data?.findings ?? [];
  const targetNames = useMemo(() => [...new Set((targets?.findings ?? []).map((f) => f.target))].sort(), [targets]);
  const openFp = params.get("open");

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
    setSelected(new Set());
  }

  function openFinding(fp: string | null) {
    const next = new URLSearchParams(params);
    if (fp) next.set("open", fp);
    else next.delete("open");
    setParams(next);
  }

  function toggle(fp: string) {
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(fp)) next.delete(fp);
      else next.add(fp);
      return next;
    });
  }

  async function bulk(status: Status) {
    setBulkError(null);
    if (needsReason(status)) {
      setDialog(status);
      return;
    }
    try {
      await api("/findings/status", { method: "POST", body: JSON.stringify({ fingerprints: [...selected], status }) });
      setSelected(new Set());
      reload();
    } catch (e) {
      setBulkError(e instanceof ApiError ? e.message : "Could not update findings.");
    }
  }

  const allSelected = rows.length > 0 && rows.every((r) => selected.has(r.fingerprint));

  return (
    <>
      <PageTitle>Findings</PageTitle>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative min-w-56 flex-1">
          <Search size={16} strokeWidth={1.5} className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-subtle" aria-hidden />
          <Input
            aria-label="Search findings"
            placeholder="Search title, asset or check"
            defaultValue={params.get("q") ?? ""}
            onKeyDown={(e) => e.key === "Enter" && setFilter("q", e.currentTarget.value)}
            onBlur={(e) => setFilter("q", e.currentTarget.value)}
            className="pl-9"
          />
        </div>
        <Filter label="Severity" value={params.get("severity")} options={SEVERITIES} onChange={(v) => setFilter("severity", v)} />
        <Filter label="Category" value={params.get("category")} options={CATEGORIES} format={categoryLabel} onChange={(v) => setFilter("category", v)} />
        <Filter label="Status" value={params.get("status")} options={STATUSES} format={statusLabel} onChange={(v) => setFilter("status", v)} />
        <Filter label="Change" value={params.get("change")} options={["new", "regressed", "unchanged"]} onChange={(v) => setFilter("change", v)} />
        {targetNames.length > 1 && (
          <Filter label="Target" value={params.get("target")} options={targetNames} format={(s) => s} onChange={(v) => setFilter("target", v)} />
        )}
      </div>

      {selected.size > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-xl border border-border bg-surface px-4 py-2">
          <span className="tabular mr-2 text-[13px] text-muted">{selected.size} selected</span>
          <Button size="sm" onClick={() => bulk("accepted-risk")}>Accept risk</Button>
          <Button size="sm" onClick={() => bulk("false-positive")}>False positive</Button>
          <Button size="sm" onClick={() => bulk("open")}>Reopen</Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>Clear</Button>
          {bulkError && <span className="text-[13px] text-critical-fg">{bulkError}</span>}
        </div>
      )}

      {error ? (
        <ErrorNote message={error} />
      ) : loading && !data ? (
        <Spinner />
      ) : rows.length === 0 ? (
        <EmptyState icon={ListChecks}>{query.toString() ? "No findings match these filters." : "No findings in the latest scans."}</EmptyState>
      ) : (
        <div className="overflow-hidden rounded-xl border border-border bg-surface">
          <div className="max-h-[calc(100vh-280px)] overflow-auto">
            <table className="w-full min-w-[720px] border-collapse text-left">
              <thead className="sticky top-0 z-10 bg-surface">
                <tr className="border-b border-border text-[12px] font-medium text-muted">
                  <th className="w-10 px-4 py-3">
                    <input
                      type="checkbox"
                      aria-label="Select all"
                      checked={allSelected}
                      onChange={() => setSelected(allSelected ? new Set() : new Set(rows.map((r) => r.fingerprint)))}
                    />
                  </th>
                  <th className="px-2 py-3 font-medium">Finding</th>
                  <th className="px-2 py-3 font-medium">Asset</th>
                  <th className="px-2 py-3 font-medium">Category</th>
                  <th className="px-2 py-3 font-medium">Change</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <tr
                    key={`${f.target}:${f.fingerprint}`}
                    onClick={() => openFinding(f.fingerprint)}
                    className={`h-12 cursor-pointer border-b border-border transition-colors duration-150 last:border-0 hover:bg-surface-2 ${
                      selected.has(f.fingerprint) ? "bg-accent-subtle" : ""
                    }`}
                  >
                    <td className="px-4" onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" aria-label={`Select ${f.title}`} checked={selected.has(f.fingerprint)} onChange={() => toggle(f.fingerprint)} />
                    </td>
                    <td className="max-w-0 px-2">
                      <div className="flex items-center gap-3">
                        <SeverityDot severity={f.severity} />
                        <span className="truncate text-[14px]">{f.title}</span>
                      </div>
                    </td>
                    <td className="max-w-0 px-2">
                      <span className="block truncate font-mono text-[12px] text-muted">{f.location ? `${f.asset.value} (${f.location})` : f.asset.value}</span>
                    </td>
                    <td className="px-2 text-[13px] whitespace-nowrap text-muted">{categoryLabel(f.category)}</td>
                    <td className="px-2">{f.change !== "unchanged" && <ChangePill change={f.change} />}</td>
                    <td className="px-4 text-[13px] whitespace-nowrap text-muted">{statusLabel(f.status)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {openFp && <FindingPanel fingerprint={openFp} onClose={() => openFinding(null)} onChanged={reload} />}
      {dialog && (
        <StatusDialog
          status={dialog}
          fingerprints={[...selected]}
          onCancel={() => setDialog(null)}
          onDone={() => {
            setDialog(null);
            setSelected(new Set());
            reload();
          }}
        />
      )}
    </>
  );
}

function ChangePill({ change }: { change: string }) {
  return change === "regressed" ? <Pill className="bg-high/12 text-high-fg">Regressed</Pill> : <Pill className="bg-accent-subtle text-text">New</Pill>;
}

function Filter({
  label,
  value,
  options,
  format = capitalize,
  onChange,
}: {
  label: string;
  value: string | null;
  options: readonly string[];
  format?: (s: string) => string;
  onChange: (v: string) => void;
}) {
  return (
    <select
      aria-label={label}
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value)}
      className={`h-9 rounded-lg border bg-bg px-3 text-[13px] ${value ? "border-border-strong text-text" : "border-border text-muted"}`}
    >
      <option value="">{label}: all</option>
      {options.map((o) => (
        <option key={o} value={o}>
          {format(o)}
        </option>
      ))}
    </select>
  );
}
