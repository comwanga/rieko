// Pure mapping from API responses to what the Overview shows. Every value
// rendered comes from a field of a response; absent fields produce no row.
import type { Status } from "./api";

// ─── Response types for the inspection endpoints ───

interface Connection {
  connected: boolean;
  last_attempt: string;
  last_success: string | null;
}

export interface BitcoinCoreSnapshot {
  network: string;
  block_height: number;
  header_height: number;
  synchronized: boolean;
  observed_at: string;
}

export interface LightningSnapshot {
  node_id: string;
  synced_to_chain: boolean;
  active_channels: number;
  inactive_channels: number;
  observed_at: string;
}

export interface BitcoinInspection {
  state: (Connection & { snapshot: BitcoinCoreSnapshot | null }) | null;
}

export interface LightningInspection {
  state: (Connection & { snapshot: LightningSnapshot | null }) | null;
}

/** Serde's default form of the backend's `SourceState` enum. */
export type SourceState =
  | "Fixture"
  | { LndRest: { connected: boolean } }
  | { BtcPayGreenfield: { connected: boolean } };

export interface BtcPayInspection {
  state: {
    source: SourceState;
    last_attempt: string | null;
    last_success: string | null;
    source_data_at: string | null;
  } | null;
}

// ─── View model ───

export type BadgeKind = "ok" | "warning" | "critical" | "neutral";
export interface Badge { kind: BadgeKind; label: string }
export interface Row { label: string; value: string; mono?: boolean }
export interface TimeLabel { label: string; relative: string; absolute: string }

export interface CardModel {
  badge: Badge;
  rows: Row[];
  /** Further rows shown under a "Stored records" heading. */
  records?: Row[];
  /** True when the rows are the last values seen before the source became unreachable. */
  lastKnown: boolean;
  observed: TimeLabel | null;
  /** The latest attempt, shown only while the source is not connected. */
  attempt?: TimeLabel;
}

const NUMBER = new Intl.NumberFormat("en-US");
const RELATIVE = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

export function formatTime(iso: string, now: Date): { relative: string; absolute: string } {
  const at = new Date(iso);
  const seconds = Math.round((at.getTime() - now.getTime()) / 1000);
  const size = Math.abs(seconds);
  // Round the magnitude so past and future times round alike (Math.round(-1.5) is -1).
  const units = (per: number) => Math.sign(seconds) * Math.round(size / per);
  const relative = size < 60 ? RELATIVE.format(seconds, "second")
    : size < 3600 ? RELATIVE.format(units(60), "minute")
      : size < 86400 ? RELATIVE.format(units(3600), "hour")
        : RELATIVE.format(units(86400), "day");
  return { relative, absolute: at.toLocaleString() };
}

function timeLabel(label: string, iso: string, now: Date): TimeLabel {
  return { label, ...formatTime(iso, now) };
}

function timeValue(iso: string, now: Date): string {
  const time = formatTime(iso, now);
  return `${time.relative} (${time.absolute})`;
}

const yesNo = (value: boolean) => (value ? "Yes" : "No");

const NOT_OBSERVED: CardModel = {
  badge: { kind: "neutral", label: "Not observed" }, rows: [], lastKnown: false, observed: null,
};

/** Badges before MS-3.1: only what is known about reachability. */
function connectionBadge(connected: boolean, lastSuccess: string | null): Badge {
  if (connected) return { kind: "ok", label: "Connected" };
  if (lastSuccess === null) return { kind: "critical", label: "Never connected" };
  return { kind: "critical", label: "Disconnected" };
}

function polledCard<S extends { observed_at: string }>(
  state: (Connection & { snapshot: S | null }) | null,
  now: Date,
  rows: (snapshot: S) => Row[],
): CardModel {
  if (!state) return NOT_OBSERVED;
  const badge = connectionBadge(state.connected, state.last_success);
  const snapshot = state.snapshot;
  const attempt = timeLabel("Last attempt", state.last_attempt, now);
  if (!snapshot) return { badge, rows: [], lastKnown: false, observed: attempt };
  return {
    badge,
    rows: rows(snapshot),
    lastKnown: !state.connected,
    observed: timeLabel(state.connected ? "Observed" : "Last observed", snapshot.observed_at, now),
    attempt: state.connected ? undefined : attempt,
  };
}

export function coreCard(inspection: BitcoinInspection, now: Date): CardModel {
  return polledCard(inspection.state, now, snapshot => [
    { label: "Network", value: snapshot.network },
    { label: "Block height", value: NUMBER.format(snapshot.block_height) },
    { label: "Header height", value: NUMBER.format(snapshot.header_height) },
    { label: "Synchronized", value: yesNo(snapshot.synchronized) },
  ]);
}

export function lightningCard(inspection: LightningInspection, now: Date): CardModel {
  return polledCard(inspection.state, now, snapshot => [
    { label: "Node ID", value: snapshot.node_id, mono: true },
    { label: "Synced to chain", value: yesNo(snapshot.synced_to_chain) },
    { label: "Active channels", value: NUMBER.format(snapshot.active_channels) },
    { label: "Inactive channels", value: NUMBER.format(snapshot.inactive_channels) },
  ]);
}

export function btcpayCard(inspection: BtcPayInspection, now: Date): CardModel {
  const state = inspection.state;
  // The state row is shared with other sources, and Core or LND polling create
  // it with a default "Fixture" source (finding M2b). Only a Greenfield source
  // is evidence of BTCPay.
  if (!state || typeof state.source !== "object" || !("BtcPayGreenfield" in state.source)) return NOT_OBSERVED;
  const { connected } = state.source.BtcPayGreenfield;
  const rows: Row[] = [];
  if (state.last_success) rows.push({ label: "Last successful poll", value: timeValue(state.last_success, now) });
  if (state.last_attempt) rows.push({ label: "Last attempt", value: timeValue(state.last_attempt, now) });
  if (state.source_data_at) rows.push({ label: "Data as of", value: timeValue(state.source_data_at, now) });
  return {
    badge: connectionBadge(connected, state.last_success),
    rows,
    lastKnown: !connected && state.last_success !== null,
    observed: state.last_success ? timeLabel(connected ? "Observed" : "Last observed", state.last_success, now) : null,
  };
}

const PIPELINE: Record<string, Badge> = {
  healthy: { kind: "ok", label: "Healthy" },
  degraded: { kind: "warning", label: "Degraded" },
  unhealthy: { kind: "critical", label: "Unhealthy" },
  not_initialized: { kind: "neutral", label: "Not initialized" },
};

/** The backend's overall state, shown literally. It covers Rieko's own pipeline. */
export function pipelineBadge(overall: string): Badge {
  return PIPELINE[overall] ?? { kind: "neutral", label: overall };
}

const COMPONENT: Record<string, string> = {
  not_configured: "Not configured", configured: "Configured, not yet verified", healthy: "Working", failing: "Failing",
};
const component = (value: string) => COMPONENT[value] ?? value;

export function riekoCard(status: Status, activeFindings: string | null, now: Date): CardModel {
  const rows: Row[] = [
    { label: "Version", value: `v${status.version}` },
    { label: "Schema", value: String(status.schema_version) },
    { label: "Database integrity", value: status.integrity },
    { label: "Build", value: status.read_only ? "Read-only" : "Node mutation capable" },
  ];
  if (activeFindings !== null) rows.push({ label: "Active findings", value: activeFindings });
  // Only the scan, monitor and Greenfield paths record an ingestion success;
  // without one the reported source is a default value (finding M2b).
  if (status.last_ingestion?.success && status.source) rows.push({ label: "Channel data source", value: status.source });
  rows.push(
    { label: "LLM", value: component(status.llm) },
    { label: "Alerts", value: component(status.alert_sink) },
    { label: "Cleanup", value: component(status.cleanup) },
  );
  const counts = status.counts;
  const records: Row[] = [
    { label: "Findings (all)", value: NUMBER.format(counts.findings) },
    { label: "Recommendations", value: NUMBER.format(counts.recommendations) },
    {
      label: "Simulations",
      value: `${NUMBER.format(counts.simulations)} (completed ${counts.simulation_completed}, failed ${counts.simulation_failed}, stale ${counts.simulation_stale})`,
    },
    { label: "Snapshot rows", value: NUMBER.format(counts.channel_snapshots) },
    { label: "Audit entries", value: NUMBER.format(counts.audit) },
  ];
  const cycle = status.last_cycle?.success;
  const pipeline = pipelineBadge(status.overall);
  return {
    // Labelled so it reads as Rieko's pipeline state, which does not yet cover
    // Bitcoin Core or LND (finding M1).
    badge: { kind: pipeline.kind, label: `Pipeline: ${pipeline.label}` },
    rows,
    records,
    lastKnown: false,
    observed: cycle ? timeLabel("Last detector cycle", cycle, now) : null,
  };
}

/** A full page of results means there may be more. */
export function findingsCount(returned: number, limit: number): string {
  return returned >= limit ? `${limit}+` : String(returned);
}
