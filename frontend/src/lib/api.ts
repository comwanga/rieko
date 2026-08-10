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

export async function post<T>(path: string, body: unknown): Promise<T> {
  const resp = await fetch(apiUrl(path), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const text = await resp.text();
    let detail = text;
    try {
      const parsed = JSON.parse(text);
      if (typeof parsed.message === "string") detail = parsed.message;
    } catch {
      /* use raw text */
    }
    throw new Error(`${resp.status} ${detail}`);
  }
  return (await resp.json()) as T;
}

// ─── Base types shared across routes ───

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
    simulation_completed: number;
    simulation_failed: number;
    simulation_stale: number;
  };
}

export interface OperationTimes {
  attempt: string | null;
  success: string | null;
}

// ─── Finding ───

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

// ─── Recommendation ───

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

// ─── ChannelSnapshot ───

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

// ─── Simulation domain types ───

export type SimulationStatus =
  | "requested"
  | "completed"
  | "unsupported"
  | "invalid_input"
  | "stale"
  | "failed";

export type SimulationConfidence = "high" | "medium" | "low" | "unknown";

export type SimulationNoticeSeverity = "info" | "warning" | "critical";

export interface LiquidityRedistributionParameters {
  source_channel: string;
  destination_channel: string;
  amount_msat: number;
}

export interface ProjectedState {
  local_ratio: number;
  local_balance_msat: number;
  remote_balance_msat: number;
  capacity_msat: number;
}

export interface ProjectedDelta {
  channel_id: string;
  local_before_msat: number;
  local_after_msat: number;
  remote_before_msat: number;
  remote_after_msat: number;
  delta_msat: number;
  clears_finding: boolean;
}

export interface Assumption {
  code: string;
  description: string;
  severity: SimulationNoticeSeverity;
}

export interface SimulationWarning {
  code: string;
  description: string;
  severity: SimulationNoticeSeverity;
}

export interface SimulationResult {
  model_id: string;
  model_version: string;
  input_hash: string;
  baseline: ProjectedState;
  projected: ProjectedState;
  deltas: ProjectedDelta[];
  assumptions: Assumption[];
  warnings: SimulationWarning[];
  confidence: SimulationConfidence;
}

export interface SimulationView {
  id: string;
  recommendation_id: string;
  finding_id: string;
  action_type: string;
  status: SimulationStatus;
  model_id: string;
  model_version: string;
  input_hash: string;
  parameters: LiquidityRedistributionParameters;
  source_observed_at: string;
  stale: boolean;
  confidence: SimulationConfidence;
  result: SimulationResult | null;
  explanation: string;
  error_code: string | null;
  requested_at: string;
  completed_at: string | null;
  no_action_executed: boolean;
}

export interface CreateSimulationCommand {
  recommendation_id: string;
  model_id: string;
  source_channel: string;
  destination_channel: string;
  amount_sats: number;
  allow_stale?: boolean;
}

export interface CreateSimulationOutcome {
  simulation: SimulationView;
  reused: boolean;
}

export interface SimulationComparison {
  recommendation_id: string;
  left: SimulationView;
  right: SimulationView;
  projected_local_ratio_delta: number;
  projected_local_balance_delta_msat: number;
  no_action_executed: boolean;
  freshness_delta_seconds: number;
  confidence_left: SimulationConfidence;
  confidence_right: SimulationConfidence;
  warnings_left: number;
  warnings_right: number;
}

export interface SimulationReport {
  rieko_version: string;
  model_id: string;
  model_version: string;
  simulation_id: string;
  input_hash: string;
  recommendation_id: string;
  finding_id: string;
  snapshot_observed_at: string;
  parameters: LiquidityRedistributionParameters;
  baseline: ProjectedState | null;
  projected: ProjectedState | null;
  deltas: ProjectedDelta[];
  assumptions: Assumption[];
  warnings: SimulationWarning[];
  confidence: SimulationConfidence;
  stale: boolean;
  explanation: string;
  generated_at: string;
  no_action_executed: boolean;
}

export interface CompareSimulationsCommand {
  left_simulation_id: string;
  right_simulation_id: string;
}

// ─── Audit ───

export interface AuditEntry {
  id: string;
  action_id: string;
  action_type: string;
  stage: ActionStage;
  actor: string;
  details: unknown;
  timestamp: string;
}
