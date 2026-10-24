// Mirrors the Go JSON shapes served by /scout/api.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "confirmed" | "likely" | "possible";
export type Status = "open" | "fixed" | "accepted-risk" | "false-positive";
export type Environment = "dev" | "staging" | "prod";
export type Change = "new" | "regressed" | "unchanged";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const STATUSES: Status[] = ["open", "fixed", "accepted-risk", "false-positive"];

export interface StackComponent {
  kind: string; // language | framework | runtime | server | package-manager
  name: string;
  version?: string;
  source?: string;
}

export interface Target {
  name: string;
  url?: string;
  repo?: string;
  environment: Environment;
  allow_active?: boolean;
  criticality?: number;
  stack?: StackComponent[];
}

export interface Asset {
  kind: string;
  value: string;
  host?: string;
  port?: number;
  method?: string;
  path?: string;
  file?: string;
  line?: number;
  exposure?: string;
}

export interface Fix {
  stack: string;
  language: string;
  code: string;
  note?: string;
}

export interface Remediation {
  what: string;
  why: string;
  how?: Fix[];
  effort: "S" | "M" | "L";
  references?: string[];
}

export interface Evidence {
  request?: string;
  response?: string;
  matched?: string;
  config_line?: string;
  notes?: string;
  redacted?: boolean;
}

export interface Finding {
  fingerprint: string;
  check_id: string;
  title: string;
  category: string;
  severity: Severity;
  cvss?: number;
  confidence: Confidence;
  asset: Asset;
  location?: string;
  evidence: Evidence;
  cwe?: string[];
  owasp?: string[];
  remediation: Remediation;
  tags?: string[];
  status: Status;
  status_reason?: string;
  status_until?: string;
  status_by?: string;
  first_seen: string;
  last_seen: string;
}

export interface FindingRow extends Finding {
  target: string;
  scan_id: string;
  change: Change;
}

export interface CategoryScore {
  category: string;
  score: number;
  grade: string;
  risk: number;
  findings: number;
  worst: Severity;
}

export interface Cap {
  grade: string;
  reason: string;
  fingerprint: string;
  title: string;
}

export interface Report {
  score: number;
  grade: string;
  categories: CategoryScore[] | null;
  uncapped: number;
  caps?: Cap[];
}

export interface FixItem {
  fingerprint: string;
  check_id: string;
  title: string;
  severity: Severity;
  asset: string;
  effort: "S" | "M" | "L";
  points: number;
  priority: number;
}

export interface TrendPoint {
  at: string;
  score: number;
  grade: string;
}

export interface TargetOverview {
  target: Target;
  scan_id: string;
  at: string;
  mode: string;
  report: Report;
  fix_next: FixItem[] | null;
  open: Partial<Record<Severity, number>>;
  trend: TrendPoint[] | null;
  modes: string[] | null;
  scans: number;
}

export interface Overview {
  app: string;
  environment: Environment;
  targets: TargetOverview[];
  configured: Target[] | null;
  killed: boolean;
}

export interface HistoryEntry {
  scan_id: string;
  at: string;
  severity: Severity;
  status: Status;
}

export interface CheckProgress {
  id: string;
  findings: number;
  error?: string;
}

export interface ScanProgress {
  id: string;
  started: string;
  total: number;
  done: number;
  findings: number;
  checks: CheckProgress[] | null;
  finished: boolean;
  error?: string;
}

export interface Settings {
  app_name: string;
  environment: Environment;
  mode: string;
  targets: Target[] | null;
  scope: { hosts?: string[]; include_paths?: string[]; exclude_paths?: string[] };
  criticality: { host?: string; path_prefix?: string; value: number }[] | null;
  rate_limit: number;
  concurrency: number;
  check_timeout_ns: number;
  retention_ns: number;
  window?: { start: string; end: string; days?: string[]; timezone?: string };
  version: string;
}
