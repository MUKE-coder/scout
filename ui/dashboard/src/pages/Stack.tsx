import { useState } from "react";
import { Link } from "react-router";
import { Boxes } from "lucide-react";
import { useApi } from "../lib/useApi";
import type { Overview, FindingRow, StackComponent } from "../lib/types";
import { Card, PageTitle, Spinner } from "../components/ui";
import { EmptyState, ErrorNote } from "../components/EmptyState";
import { Recommendation } from "../components/Recommendation";
import { SeverityBadge } from "../components/Severity";

const DEP_CHECKS = new Set(["code.vulnerable-deps", "code.go-vulncheck"]);
const EXPLOITED = "[Exploited] ";
const KIND_LABEL: Record<string, string> = {
  language: "Languages",
  framework: "Frameworks",
  runtime: "Runtimes",
  server: "Servers",
  "package-manager": "Package managers",
};

export function Stack() {
  const { data, error, loading } = useApi<Overview>("/overview");
  const findings = useApi<{ findings: FindingRow[] }>("/findings").data;
  const [selected, setSelected] = useState<string | null>(null);

  if (loading && !data) return <Spinner />;
  if (error) return <ErrorNote message={error} />;
  if (!data || data.targets.length === 0) {
    return (
      <>
        <PageTitle>Stack &amp; dependencies</PageTitle>
        <EmptyState icon={Boxes}>
          Run a scan first. Source scans (<code className="font-mono text-[13px]">scout scan --repo .</code>) detect the
          language, framework and dependency vulnerabilities.
        </EmptyState>
      </>
    );
  }

  const targets = data.targets;
  const current = targets.find((t) => t.target.name === selected) ?? targets[0];
  const stack = current.target.stack ?? [];
  const deps = (findings?.findings ?? []).filter(
    (f) => DEP_CHECKS.has(f.check_id) && f.target === current.target.name,
  );

  const byKind: Record<string, StackComponent[]> = {};
  for (const c of stack) (byKind[c.kind] ??= []).push(c);

  return (
    <>
      <PageTitle
        action={
          targets.length > 1 && (
            <select
              aria-label="Target"
              value={current.target.name}
              onChange={(e) => setSelected(e.target.value)}
              className="h-9 rounded-lg border border-border bg-bg px-3 text-[14px]"
            >
              {targets.map((t) => (
                <option key={t.target.name} value={t.target.name}>
                  {t.target.name}
                </option>
              ))}
            </select>
          )
        }
      >
        Stack &amp; dependencies
      </PageTitle>

      <Recommendation tone={deps.length ? "warn" : "info"}>
        {deps.length
          ? `${deps.length} dependency vulnerabilit${deps.length > 1 ? "ies" : "y"} found. Update each package to its fixed version, then re-scan.`
          : stack.length
            ? "No known-vulnerable dependencies right now. Re-scan regularly — new advisories are published daily."
            : "No stack detected yet. Run a source scan (scout scan --repo .) to identify the language, framework and dependencies."}
      </Recommendation>

      {/* Detected stack */}
      <Card className="mb-6">
        <h2 className="mb-4 text-[16px] font-medium">Detected stack</h2>
        {stack.length === 0 ? (
          <p className="text-[13px] text-muted">
            Nothing detected. Stack is identified from repo manifests and the app's server headers.
          </p>
        ) : (
          <div className="flex flex-col gap-4">
            {Object.keys(KIND_LABEL)
              .filter((k) => byKind[k]?.length)
              .map((kind) => (
                <div key={kind} className="grid grid-cols-[120px_1fr] items-start gap-3">
                  <span className="text-[13px] text-subtle">{KIND_LABEL[kind]}</span>
                  <div className="flex flex-wrap gap-2">
                    {byKind[kind].map((c) => (
                      <span
                        key={c.name}
                        title={c.source ? `from ${c.source}` : undefined}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface-2 px-2.5 py-1 text-[13px]"
                      >
                        <span className="font-medium">{c.name}</span>
                        {c.version && <span className="font-mono text-[12px] text-muted">{c.version}</span>}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
          </div>
        )}
      </Card>

      {/* Vulnerable dependencies */}
      <Card className="p-0">
        <div className="flex items-center justify-between border-b border-border px-6 py-4">
          <h2 className="text-[16px] font-medium">Vulnerable dependencies</h2>
          <span className="text-[13px] text-muted">
            <span className="tabular font-medium text-text">{deps.length}</span> found
          </span>
        </div>
        {deps.length === 0 ? (
          <p className="px-6 py-6 text-[13px] text-muted">No known-vulnerable dependencies. ✅</p>
        ) : (
          <table className="w-full border-collapse text-left text-[14px]">
            <thead>
              <tr className="text-[12px] text-subtle">
                <th className="px-6 py-3 font-medium">Severity</th>
                <th className="px-6 py-3 font-medium">Package</th>
                <th className="px-6 py-3 font-medium">Advisory</th>
              </tr>
            </thead>
            <tbody>
              {deps.map((f) => (
                <tr key={f.fingerprint} className="border-t border-border">
                  <td className="px-6 py-3">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="px-6 py-3 font-mono text-[13px]">{f.asset?.value}</td>
                  <td className="px-6 py-3">
                    {f.title.startsWith(EXPLOITED) && (
                      <span
                        title="In CISA's Known Exploited Vulnerabilities catalog — exploited in the wild"
                        className="mr-2 inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                        style={{
                          color: "var(--sev-critical)",
                          backgroundColor: "color-mix(in srgb, var(--sev-critical) 14%, transparent)",
                        }}
                      >
                        Exploited
                      </span>
                    )}
                    <Link to={`/findings?open=${f.fingerprint}`} className="hover:underline">
                      {f.title.startsWith(EXPLOITED) ? f.title.slice(EXPLOITED.length) : f.title}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
