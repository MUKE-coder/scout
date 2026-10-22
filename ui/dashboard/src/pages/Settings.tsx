import { useState, type ReactNode } from "react";
import { Download, OctagonX, Play } from "lucide-react";
import { useApi } from "../lib/useApi";
import { API, ApiError, api, getToken } from "../lib/api";
import { useLive } from "../lib/live";
import type { Settings as SettingsData } from "../lib/types";
import { capitalize } from "../lib/format";
import { Button, Card, PageTitle, Spinner } from "../components/ui";
import { ErrorNote } from "../components/EmptyState";
import { Pill } from "../components/Severity";

const capText: Record<string, string> = {
  dev: "Every mode is allowed.",
  staging: "Up to active; intrusive needs a per-target opt-in.",
  prod: "Up to safe; active needs a per-target opt-in and verified ownership. Intrusive is never allowed.",
};

const nsToText = (ns: number) => {
  const s = ns / 1e9;
  if (s >= 86400) return `${Math.round(s / 86400)} days`;
  if (s >= 3600) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s)} s`;
};

export function Settings() {
  const { data, error, loading } = useApi<SettingsData>("/settings");
  if (loading && !data) return <Spinner />;
  if (error) return <ErrorNote message={error} />;
  if (!data) return null;

  const targets = data.targets ?? [];
  return (
    <>
      <PageTitle>Settings</PageTitle>
      <p className="-mt-4 mb-8 text-muted">
        These are the settings Scout is running with. Change them in <code className="font-mono text-[13px]">scout.yaml</code> or with{" "}
        <code className="font-mono text-[13px]">SCOUT_*</code> environment variables, then restart.
      </p>

      <div className="flex flex-col gap-8">
        <Section title="Targets">
          {targets.length === 0 ? (
            <p className="text-[13px] text-muted">No targets configured, so the dashboard cannot start scans.</p>
          ) : (
            <ul className="flex flex-col">
              {targets.map((t) => (
                <li key={t.name} className="flex flex-wrap items-center gap-3 border-b border-border py-3 last:border-0">
                  <span className="w-32 text-[14px] font-medium">{t.name}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-muted">{t.url || t.repo}</span>
                  <Pill className="bg-surface-2 text-muted">{t.environment}</Pill>
                  {t.allow_active && <Pill className="bg-accent-subtle text-text">Active opt-in</Pill>}
                  {t.criticality ? <span className="tabular text-[12px] text-subtle">criticality {t.criticality}</span> : null}
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Modes">
          <Rows
            rows={[
              ["Environment", capitalize(data.environment)],
              ["Requested mode", capitalize(data.mode)],
              ["Environment cap", capText[data.environment] ?? ""],
            ]}
          />
        </Section>

        <Section title="Scope">
          <Rows
            rows={[
              ["Hosts", list(data.scope.hosts, "Each target's own host")],
              ["Include paths", list(data.scope.include_paths, "All paths")],
              ["Exclude paths", list(data.scope.exclude_paths, "None")],
            ]}
          />
        </Section>

        <Section title="Limits and schedule">
          <Rows
            rows={[
              ["Rate limit", <span className="tabular">{data.rate_limit} requests/s per host</span>],
              ["Concurrency", <span className="tabular">{data.concurrency} checks at once</span>],
              ["Check timeout", nsToText(data.check_timeout_ns)],
              ["History retention", nsToText(data.retention_ns)],
              [
                "Scan window",
                data.window
                  ? `${data.window.start}–${data.window.end}${data.window.days?.length ? ` on ${data.window.days.join(", ")}` : ""}${data.window.timezone ? ` (${data.window.timezone})` : ""}`
                  : "Any time",
              ],
              ["Scheduled scans", <span className="text-muted">Not available yet: scheduling arrives in a later release.</span>],
            ]}
          />
        </Section>

        <Section title="Data export">
          <p className="mb-4 text-[13px] text-muted">Download the latest findings of every target.</p>
          <div className="flex flex-wrap gap-2">
            <ExportButton format="json" />
            <ExportButton format="csv" />
          </div>
        </Section>

        <DangerZone />

        <p className="text-[12px] text-subtle">Scout {data.version}</p>
      </div>
    </>
  );
}

function list(values: string[] | undefined, empty: string): ReactNode {
  if (!values || values.length === 0) return <span className="text-muted">{empty}</span>;
  return <span className="font-mono text-[13px]">{values.join(", ")}</span>;
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <h2 className="mb-4 text-[18px] font-semibold">{title}</h2>
      {children}
    </Card>
  );
}

function Rows({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="flex flex-col">
      {rows.map(([k, v]) => (
        <div key={k} className="grid gap-1 border-b border-border py-3 last:border-0 sm:grid-cols-[180px_1fr] sm:gap-4">
          <dt className="text-[13px] text-muted">{k}</dt>
          <dd className="text-[14px]">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

// Downloads go through fetch so the token travels in a header, not the URL.
function ExportButton({ format }: { format: "json" | "csv" }) {
  const [busy, setBusy] = useState(false);
  async function download() {
    setBusy(true);
    try {
      const res = await fetch(`${API}/export?format=${format}`, { headers: { Authorization: `Bearer ${getToken() ?? ""}` } });
      if (!res.ok) throw new Error(res.statusText);
      const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") ?? "")?.[1] ?? `scout.${format}`;
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Button onClick={download} disabled={busy}>
      <Download size={16} strokeWidth={1.5} aria-hidden />
      {format.toUpperCase()}
    </Button>
  );
}

function DangerZone() {
  const { killed, refresh } = useLive();
  const [error, setError] = useState<string | null>(null);
  async function toggle() {
    setError(null);
    try {
      await api(killed ? "/resume" : "/kill", { method: "POST" });
      refresh();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach Scout.");
    }
  }
  return (
    <div className="rounded-xl border border-critical/40 bg-surface p-6">
      <h2 className="mb-2 text-[18px] font-semibold">Danger zone</h2>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <p className="max-w-xl text-[13px] text-muted">
          The kill switch stops every running scan from sending further requests and blocks new scans until you resume.
        </p>
        <Button variant={killed ? "secondary" : "danger"} onClick={toggle}>
          {killed ? <Play size={16} strokeWidth={1.5} aria-hidden /> : <OctagonX size={16} strokeWidth={1.5} aria-hidden />}
          {killed ? "Resume scanning" : "Engage kill switch"}
        </Button>
      </div>
      {error && <p className="mt-3 text-[13px] text-critical-fg">{error}</p>}
    </div>
  );
}
