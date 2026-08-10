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
  schema_version: number;
  read_only: boolean;
  integrity: string;
  overall: string;
  source: string | null;
  source_data_at: string | null;
  last_ingestion: OperationTimes | null;
  last_cycle: OperationTimes | null;
  llm: string;
  alert_sink: string;
  cleanup: string;
  last_cleanup: OperationTimes | null;
  counts: {
    findings: number;
    recommendations: number;
    simulations: number;
    audit: number;
    channel_snapshots: number;
  };
}

export interface OperationTimes {
  attempt: string | null;
  success: string | null;
}

export interface Finding {
  id: string;
  detector: string;
  detector_version: string;
  schema_version: number;
  severity: Severity;
  node: string | null;
  channel: string | null;
  evidence: { key: string; value: unknown }[];
  provenance: FindingProvenance | null;
  explanation: string | null;
  timestamp: string;
  first_seen_at: string;
  last_seen_at: string;
  lifecycle: "active" | "resolved";
}

export interface FindingProvenance {
  network?: "mainnet" | "testnet" | "signet" | "regtest" | null;
  source:
    | { kind: "fixture"; redacted_hash: string }
    | { kind: "lnd"; redacted_endpoint: string; configured_node: string };
  producers: {
    name: string;
    version: string;
    role: "ingest" | "normalizer" | "detector";
  }[];
  observation:
    | {
        kind: "channel_state";
        channel_id: string;
        snapshot: {
          network?: "mainnet" | "testnet" | "signet" | "regtest" | null;
          observed_at: string;
          state_digest: string;
        };
      }
    | {
        kind: "channel_window";
        channel_id: string;
        snapshots: {
          network?: "mainnet" | "testnet" | "signet" | "regtest" | null;
          observed_at: string;
          state_digest: string;
        }[];
      };
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
  node_id: string | null;
  network: "mainnet" | "testnet" | "signet" | "regtest" | null;
  state_digest: string | null;
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
  recommendation_id: string;
  finding_id: string;
  action_type: string;
  status: "requested" | "completed" | "unsupported" | "invalid_input" | "stale" | "failed";
  model_id: string;
  model_version: string;
  input_hash: string;
  parameters: {
    source_channel: string;
    destination_channel: string;
    amount_msat: number;
  };
  source_observed_at: string;
  stale: boolean;
  confidence: "high" | "medium" | "low" | "unknown";
  result: unknown | null;
  no_action_executed: true;
  requested_at: string;
  completed_at: string | null;
  error_code: string | null;
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
