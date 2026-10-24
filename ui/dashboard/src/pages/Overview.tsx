import { Link } from "react-router";
import { ArrowRight, Radar } from "lucide-react";
import { useApi } from "../lib/useApi";
import { useTarget } from "../lib/target";
import type { Environment, Overview as OverviewData, Severity, TargetOverview } from "../lib/types";
import { SEVERITIES } from "../lib/types";
import { ago, categoryLabel, effortLabel } from "../lib/format";
import { Card, PageTitle, Spinner } from "../components/ui";
import { GradeRing } from "../components/GradeRing";
import { CoveragePanel } from "../components/CoveragePanel";
import { TrendChart } from "../components/TrendChart";
import { EmptyState, ErrorNote } from "../components/EmptyState";
import { SeverityDot, severityVar, gradeVar } from "../components/Severity";

export function Overview() {
  const { data, error, loading } = useApi<OverviewData>("/overview");
  const { current: selectedTarget } = useTarget();

  if (loading && !data) return <Spinner />;
  if (error) return <ErrorNote message={error} />;
  if (!data) return null;

  const targets = data.targets;
  if (targets.length === 0) {
    return (
      <>
        <PageTitle>Overview</PageTitle>
        <EmptyState icon={Radar}>
          No scans yet. Use <span className="font-medium text-text">New scan</span> in the top bar, or run{" "}
          <code className="font-mono text-[13px]">scout scan --target &lt;url&gt;</code> against this database.
        </EmptyState>
      </>
    );
  }

  const current = targets.find((t) => t.target.name === selectedTarget?.name) ?? targets[0];
  return (
    <>
      <PageTitle>Overview</PageTitle>

      <div className="flex flex-col gap-8">
        <div className="grid gap-4 lg:grid-cols-[auto_1fr]">
          <GradeCard t={current} />
          <Card>
            <h2 className="mb-4 text-[16px] font-medium">Score, last 30 days</h2>
            <TrendChart points={current.trend ?? []} />
          </Card>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <Subscores t={current} />
          <FixNext t={current} />
        </div>

        <CoveragePanel current={current} data={data} />

        <EnvCards targets={targets} />
      </div>
    </>
  );
}

function GradeCard({ t }: { t: TargetOverview }) {
  const r = t.report;
  return (
    <Card className="flex flex-col items-center gap-4 sm:flex-row sm:items-start lg:flex-col lg:items-center xl:flex-row xl:items-start">
      <GradeRing score={r.score} grade={r.grade} />
      <div className="flex min-w-48 flex-col gap-3">
        <div>
          <div className="text-[16px] font-medium">{t.target.name}</div>
          <div className="font-mono text-[12px] text-muted">{t.target.url || t.target.repo}</div>
          <div className="mt-1 text-[12px] text-subtle">
            {t.target.environment} · {t.mode} mode · scanned {ago(t.at)}
          </div>
        </div>
        <OpenCounts open={t.open} />
        {r.caps?.[0] && (
          <p className="text-[12px] text-muted">
            Capped at <span style={{ color: gradeVar(r.caps[0].grade) }}>{r.caps[0].grade}</span>: {r.caps[0].reason}.
          </p>
        )}
      </div>
    </Card>
  );
}

function OpenCounts({ open }: { open: Partial<Record<Severity, number>> }) {
  const total = SEVERITIES.reduce((n, s) => n + (open[s] ?? 0), 0);
  if (total === 0) return <p className="text-[13px] text-ok-fg">No open findings.</p>;
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1">
      {SEVERITIES.filter((s) => open[s]).map((s) => (
        <li key={s} className="flex items-center gap-2 text-[13px]">
          <SeverityDot severity={s} />
          <span className="tabular font-medium">{open[s]}</span>
          <span className="text-muted">{s}</span>
        </li>
      ))}
    </ul>
  );
}

function Subscores({ t }: { t: TargetOverview }) {
  const cats = t.report.categories ?? [];
  return (
    <Card>
      <h2 className="mb-4 text-[16px] font-medium">Categories</h2>
      {cats.length === 0 ? (
        <p className="text-[13px] text-muted">No checks ran in the latest scan.</p>
      ) : (
        <ul className="flex flex-col gap-3">
          {cats.map((c) => (
            <li key={c.category} className="grid grid-cols-[96px_1fr_48px] items-center gap-3 text-[13px]">
              <span className="text-muted">{categoryLabel(c.category)}</span>
              <span className="h-1.5 overflow-hidden rounded-full bg-border">
                <span
                  className="block h-full rounded-full"
                  style={{ width: `${c.score}%`, background: c.findings ? severityVar[c.worst] : "var(--ok)" }}
                />
              </span>
              <span className="tabular text-right font-medium">{Math.round(c.score)}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function FixNext({ t }: { t: TargetOverview }) {
  const items = t.fix_next ?? [];
  return (
    <Card>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-[16px] font-medium">Fix next</h2>
        <Link to="/findings" className="flex items-center gap-1 text-[13px] text-muted hover:text-text">
          All findings <ArrowRight size={16} strokeWidth={1.5} aria-hidden />
        </Link>
      </div>
      {items.length === 0 ? (
        <p className="text-[13px] text-muted">Nothing to fix. Nice.</p>
      ) : (
        <ol className="flex flex-col">
          {items.map((it, i) => (
            <li key={it.fingerprint} className="flex items-center gap-3 border-b border-border py-3 last:border-0">
              <span className="tabular w-4 text-[13px] text-subtle">{i + 1}</span>
              <SeverityDot severity={it.severity} />
              <Link to={`/findings?open=${it.fingerprint}`} className="min-w-0 flex-1 truncate text-[14px] hover:underline">
                {it.title}
              </Link>
              <span className="tabular text-[12px] text-ok-fg">+{it.points.toFixed(1)}</span>
              <span className="w-14 text-right text-[12px] text-subtle">{effortLabel[it.effort]}</span>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}

const ENVS: Environment[] = ["dev", "staging", "prod"];

// Environment cards: per environment, how many targets and the worst grade.
function EnvCards({ targets }: { targets: TargetOverview[] }) {
  const worst = (grades: string[]) => grades.reduce((w, g) => (g > w ? g : w), "");
  return (
    <div className="grid gap-4 sm:grid-cols-3">
      {ENVS.map((env) => {
        const ts = targets.filter((t) => t.target.environment === env);
        const grade = worst(ts.map((t) => t.report.grade).filter(Boolean));
        const open = ts.reduce((n, t) => n + SEVERITIES.reduce((m, s) => m + (t.open[s] ?? 0), 0), 0);
        return (
          <Card key={env} className="p-5">
            <div className="text-[11px] font-medium tracking-[0.06em] text-subtle uppercase">{env}</div>
            {ts.length === 0 ? (
              <p className="mt-2 text-[13px] text-muted">No targets</p>
            ) : (
              <div className="mt-2 flex items-baseline justify-between">
                <span className="text-[22px] font-semibold" style={{ color: gradeVar(grade) }}>
                  {grade || "–"}
                </span>
                <span className="text-[13px] text-muted">
                  {ts.length} target{ts.length > 1 ? "s" : ""} · <span className="tabular">{open}</span> open
                </span>
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
}
