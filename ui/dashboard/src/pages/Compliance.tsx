import { useApi } from "../lib/useApi";
import type { Severity } from "../lib/types";
import { Card, PageTitle, Spinner } from "../components/ui";
import { ErrorNote } from "../components/EmptyState";
import { Recommendation } from "../components/Recommendation";

interface Cell {
  open: number;
  worst?: Severity;
}
interface Row {
  id: string;
  name: string;
  checks: number;
  targets?: Record<string, Cell>;
}
interface ComplianceData {
  targets: string[];
  owasp: Row[];
  asvs: Row[];
  mapped: number;
  total: number;
}

// Cell tints: severity color at ~12% with readable same-hue text.
const tint: Record<Severity, string> = {
  critical: "bg-critical/12 text-critical-fg",
  high: "bg-high/12 text-high-fg",
  medium: "bg-medium/12 text-medium-fg",
  low: "bg-low/12 text-low-fg",
  info: "bg-info/12 text-info-fg",
};

export function Compliance() {
  const { data, error, loading } = useApi<ComplianceData>("/compliance");
  if (loading && !data) return <Spinner />;
  if (error) return <ErrorNote message={error} />;
  if (!data) return null;

  const covered = data.owasp.filter((r) => r.checks > 0).length;
  const failing = data.owasp.filter((r) => Object.values(r.targets ?? {}).some((c) => c.open > 0));
  return (
    <>
      <PageTitle>Compliance</PageTitle>
      <Recommendation tone={failing.length ? "warn" : "ok"}>
        {failing.length
          ? `${failing.length} OWASP categor${failing.length > 1 ? "ies have" : "y has"} open findings (${failing.map((r) => r.id).join(", ")}). Each number is a to-do for that area; a dot (·) means it passed. Click a finding to see the cause and fix.`
          : `No open findings map to the OWASP Top 10 — every covered category is passing. Keep coverage up by re-scanning after changes.`}
      </Recommendation>
      <p className="-mt-4 mb-8 max-w-3xl text-muted">
        Open findings mapped to the OWASP Top 10, and which categories Scout's checks cover. {data.mapped} of {data.total} registered checks
        declare standards mappings; {covered} of 10 Top 10 categories are covered.
        {data.total === 0 && " No checks are registered yet, so nothing is covered."}
      </p>

      <Card className="mb-8 p-0">
        <h2 className="border-b border-border px-6 py-4 text-[16px] font-medium">OWASP Top 10 (2021)</h2>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] border-collapse text-left">
            <thead>
              <tr className="border-b border-border text-[12px] text-muted">
                <th className="px-6 py-3 font-medium">Category</th>
                <th className="px-3 py-3 text-right font-medium">Checks</th>
                {data.targets.map((t) => (
                  <th key={t} className="px-3 py-3 text-center font-medium">
                    {t}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.owasp.map((r) => (
                <tr key={r.id} className="h-12 border-b border-border last:border-0">
                  <td className="px-6">
                    <span className="mr-3 font-mono text-[12px] text-subtle">{r.id.replace(":2021", "")}</span>
                    <span className="text-[14px]">{r.name}</span>
                  </td>
                  <td className="tabular px-3 text-right text-[13px]">
                    {r.checks > 0 ? r.checks : <span className="text-subtle">Not covered</span>}
                  </td>
                  {data.targets.map((t) => {
                    const cell = r.targets?.[t];
                    return (
                      <td key={t} className="px-3 text-center">
                        {cell && cell.open > 0 && cell.worst ? (
                          <span className={`tabular inline-flex h-7 min-w-10 items-center justify-center rounded-md px-2 text-[13px] font-medium ${tint[cell.worst]}`}>
                            {cell.open}
                          </span>
                        ) : (
                          <span className="text-[13px] text-subtle">·</span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card>
        <h2 className="mb-1 text-[16px] font-medium">ASVS 4.0.3 coverage</h2>
        <p className="mb-4 text-[13px] text-muted">Registered checks per verification chapter.</p>
        <ul className="grid gap-x-8 gap-y-2 md:grid-cols-2">
          {data.asvs.map((r) => (
            <li key={r.id} className="flex items-center gap-3 text-[13px]">
              <span className="w-10 font-mono text-[12px] text-subtle">{r.id}</span>
              <span className="min-w-0 flex-1 truncate">{r.name}</span>
              <span className={`tabular ${r.checks ? "" : "text-subtle"}`}>{r.checks || "–"}</span>
            </li>
          ))}
        </ul>
      </Card>
    </>
  );
}
