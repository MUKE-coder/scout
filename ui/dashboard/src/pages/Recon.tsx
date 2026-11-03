import { Radar } from "lucide-react";
import { useApi } from "../lib/useApi";
import { useTarget } from "../lib/target";
import type { Overview } from "../lib/types";
import { Card, PageTitle, Spinner } from "../components/ui";
import { EmptyState, ErrorNote } from "../components/EmptyState";
import { Recommendation } from "../components/Recommendation";

export function Recon() {
  const { data, error, loading } = useApi<Overview>("/overview");
  const { current: selectedTarget } = useTarget();

  if (loading && !data) return <Spinner />;
  if (error) return <ErrorNote message={error} />;
  if (!data || data.targets.length === 0) {
    return (
      <>
        <PageTitle>Reconnaissance</PageTitle>
        <EmptyState icon={Radar}>
          Run a scan against a URL first. Scout gathers WHOIS, DNS and subdomains for the target's domain.
        </EmptyState>
      </>
    );
  }

  const current = data.targets.find((t) => t.target.name === selectedTarget?.name) ?? data.targets[0];
  const recon = current.target.recon;

  if (!recon) {
    return (
      <>
        <PageTitle>Reconnaissance</PageTitle>
        <EmptyState icon={Radar}>
          No recon for this target. Recon runs for a real domain (not localhost, an IP, or a repo-only scan).
        </EmptyState>
      </>
    );
  }

  return (
    <>
      <PageTitle>Reconnaissance</PageTitle>

      <Recommendation tone="info">
        This is the public footprint an attacker maps first (passive recon). Review the subdomains and DNS
        for anything unexpected — forgotten dev/staging hosts, dangling records — and treat the WHOIS
        contacts as a social-engineering surface.
      </Recommendation>

      {recon.whois && (
        <Card className="mb-6">
          <h2 className="mb-4 text-[16px] font-medium">WHOIS — {recon.domain}</h2>
          <dl className="grid grid-cols-1 gap-x-8 gap-y-3 sm:grid-cols-2">
            <Field label="Registrar" value={recon.whois.registrar} />
            <Field label="Organization" value={recon.whois.org} />
            <Field label="Created" value={recon.whois.created} />
            <Field label="Expires" value={recon.whois.expires} />
            <Field label="Name servers" value={recon.whois.name_servers?.join(", ")} mono wide />
            <Field label="Status" value={recon.whois.status?.join(", ")} wide />
            <Field label="Emails" value={recon.whois.emails?.join(", ")} mono wide />
          </dl>
        </Card>
      )}

      {recon.dns && (
        <Card className="mb-6">
          <h2 className="mb-4 text-[16px] font-medium">DNS records</h2>
          <dl className="flex flex-col gap-3">
            <Rec label="A" values={recon.dns.a} />
            <Rec label="AAAA" values={recon.dns.aaaa} />
            <Rec label="CNAME" values={recon.dns.cname ? [recon.dns.cname] : undefined} />
            <Rec label="MX" values={recon.dns.mx} />
            <Rec label="NS" values={recon.dns.ns} />
            <Rec label="TXT" values={recon.dns.txt} />
            <Rec label="Reverse (PTR)" values={recon.dns.ptr} />
          </dl>
        </Card>
      )}

      {recon.subdomains && recon.subdomains.length > 0 && (
        <Card>
          <div className="mb-4 flex items-baseline justify-between">
            <h2 className="text-[16px] font-medium">Subdomains</h2>
            <span className="text-[13px] text-muted">
              <span className="tabular font-medium text-text">{recon.subdomains.length}</span> via certificate transparency
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {recon.subdomains.map((s) => (
              <span key={s} className="rounded-lg border border-border bg-surface-2 px-2.5 py-1 font-mono text-[12px]">
                {s}
              </span>
            ))}
          </div>
        </Card>
      )}
    </>
  );
}

function Field({ label, value, mono, wide }: { label: string; value?: string; mono?: boolean; wide?: boolean }) {
  if (!value) return null;
  return (
    <div className={wide ? "sm:col-span-2" : ""}>
      <dt className="text-[12px] text-subtle">{label}</dt>
      <dd className={`text-[14px] ${mono ? "font-mono text-[13px] break-all" : ""}`}>{value}</dd>
    </div>
  );
}

function Rec({ label, values }: { label: string; values?: string[] }) {
  if (!values || values.length === 0) return null;
  return (
    <div className="grid grid-cols-[110px_1fr] items-start gap-3">
      <span className="text-[13px] text-subtle">{label}</span>
      <span className="font-mono text-[13px] break-all">{values.join(", ")}</span>
    </div>
  );
}
