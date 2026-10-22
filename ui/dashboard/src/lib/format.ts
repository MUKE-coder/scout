const dateFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });
const timeFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

export const shortDate = (iso: string) => dateFmt.format(new Date(iso));
export const dateTime = (iso: string) => timeFmt.format(new Date(iso));

export function ago(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const capitalize = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);

// Category names as sentence-case labels.
const categoryLabels: Record<string, string> = {
  app: "App",
  api: "API",
  auth: "Auth",
  tls: "TLS",
  headers: "Headers",
  exposure: "Exposure",
  network: "Network",
  dns: "DNS & email",
  host: "Host",
  code: "Code",
  config: "Config",
};
export const categoryLabel = (c: string) => categoryLabels[c] ?? capitalize(c);

export const effortLabel = { S: "Small", M: "Medium", L: "Large" } as const;
export const statusLabel = (s: string) => capitalize(s.replace("-", " "));
