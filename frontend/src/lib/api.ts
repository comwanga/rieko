let apiBase = "";

export function setupApiBase(base: string) {
  apiBase = base.replace(/\/$/, "");
}

export function apiUrl(path: string): string {
  return `${apiBase}${path}`;
}

export async function get<T>(path: string): Promise<T> {
  const resp = await fetch(apiUrl(path));
  if (!resp.ok) {
    throw new Error(`${resp.status} ${await resp.text()}`);
  }
  return (await resp.json()) as T;
}

export type Severity = "Info" | "Warning" | "Critical";
export type ActionStage =
  | "Recommended"
  | "Simulated"
  | "Approved"
  | "Executed"
  | "Rejected"
  | "Failed";

export interface Status {
  engine: string;
  version: string;
  read_only: boolean;
}

export interface Finding {
  id: string;
  detector: string;
  severity: Severity;
  node: string | null;
  channel: string | null;
  evidence: { key: string; value: unknown }[];
  explanation: string | null;
  timestamp: string;
}

export interface Recommendation {
  finding_id: string;
  action: {
    id: string;
    action_type: string;
    stage: ActionStage;
    target: string | null;
    params: unknown;
    summary: string;
    created_at: string;
    updated_at: string;
  };
}

export interface ChannelSnapshot {
  channel_id: string;
  local_ratio: number;
  local_balance_msat: number;
  remote_balance_msat: number;
  capacity_msat: number;
  status: string;
  ts: string;
}

export interface Simulation {
  id: string;
  action_id: string;
  finding_id: string;
  action_type: string;
  projection: {
    local_ratio_before: number;
    local_ratio_after: number;
    local_balance_msat_after: number;
    remote_balance_msat_after: number;
    delta_msat: number;
    clears_finding: boolean;
    summary: string;
  };
  created_at: string;
}

export interface AuditEntry {
  id: string;
  action_id: string;
  action_type: string;
  stage: ActionStage;
  actor: string;
  details: unknown;
  timestamp: string;
}