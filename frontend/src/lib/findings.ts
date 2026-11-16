// Types and pure helpers for the findings workflow. Every value shown comes
// from an API response; missing or unrecognised data is named as such.
import type { Recommendation } from "./api";

/** The recommendation shape the API sends, including fields `api.ts` omits. */
export interface RecommendationDetail extends Recommendation {
  rationale: {
    evidence: string[];
    preconditions: string[];
    expected_effect: string;
    risks: string[];
    limitations: string[];
    actionability: string;
  };
  lifecycle?: string;
}

export interface Row { label: string; value: string }

export interface StaleNote { tag: string; detail: string }

/**
 * Wording for a finding the API reports as stale: active, but not re-confirmed
 * for longer than the agent's threshold. It states the age of the last
 * confirmation and nothing about why. Null for any other finding, including
 * one from an agent too old to send the flag; the absence of a note says
 * nothing about the health of the finding's source.
 */
export function staleNote(
  finding: { observation_stale?: boolean },
  lastSeen: { relative: string; absolute: string },
): StaleNote | null {
  if (finding.observation_stale !== true) return null;
  return {
    tag: "Stale",
    detail: `Rieko last confirmed this finding ${lastSeen.relative} (${lastSeen.absolute}) and has not confirmed it since. `
      + "It may no longer describe the current state.",
  };
}

export function evidenceValue(value: unknown): { text: string; block: boolean } {
  if (value !== null && typeof value === "object") return { text: JSON.stringify(value, null, 2), block: true };
  return { text: String(value), block: false };
}

export interface SnapshotReference { network?: string | null; observed_at: string; state_digest: string }

export interface ProvenanceView {
  network: string | null;
  source: Row[];
  producers: { name: string; version: string; role: string }[];
  observation: { kind: string; channel: string | null; snapshots: SnapshotReference[] };
}

type Loose = Record<string, unknown>;
const text = (value: unknown) => (typeof value === "string" ? value : null);

function sourceRows(source: Loose | undefined): Row[] {
  const kind = text(source?.kind) ?? "unknown";
  const rows = (label: string, entries: [string, unknown][]): Row[] => [
    { label: "Source", value: label },
    ...entries.flatMap(([name, value]) => (text(value) ? [{ label: name, value: value as string }] : [])),
  ];
  switch (kind) {
    case "fixture":
      return rows("Fixture", [["Content hash", source?.redacted_hash], ["Configured node", source?.configured_node]]);
    case "lnd":
      return rows("LND", [["Endpoint (redacted)", source?.redacted_endpoint], ["Configured node", source?.configured_node]]);
    case "btc_pay":
      return rows("BTCPay Server", [
        ["Endpoint (redacted)", source?.redacted_endpoint], ["Configured store", source?.configured_store],
        ["Underlying node", source?.underlying_node],
      ]);
    default:
      return [{ label: "Source", value: `Unrecognised source (${kind})` }];
  }
}

/** `null` when the finding records no provenance. */
export function describeProvenance(provenance: unknown): ProvenanceView | null {
  if (!provenance || typeof provenance !== "object") return null;
  const value = provenance as Loose;
  const observation = (value.observation ?? {}) as Loose;
  const kind = text(observation.kind) ?? "unknown";
  const snapshots = kind === "channel_state" ? [observation.snapshot as SnapshotReference]
    : kind === "channel_window" ? (observation.snapshots as SnapshotReference[]) : [];
  return {
    network: text(value.network),
    source: sourceRows(value.source as Loose | undefined),
    producers: Array.isArray(value.producers) ? (value.producers as ProvenanceView["producers"]) : [],
    observation: {
      kind: kind === "channel_state" ? "Single observation"
        : kind === "channel_window" ? "Observation window" : `Unrecognised observation (${kind})`,
      channel: text(observation.channel_id),
      snapshots: snapshots.filter(Boolean),
    },
  };
}

/** The finding's recommendations among those returned, which are the latest `limit`. */
export function recommendationsFor(all: RecommendationDetail[], findingId: string, limit: number) {
  return { items: all.filter(rec => rec.finding_id === findingId), possiblyIncomplete: all.length >= limit };
}

const ACTIONABILITY: Record<string, string> = {
  Informational: "Informational",
  OperatorActionable: "Operator may choose to act",
};
export const actionabilityLabel = (value: string) => ACTIONABILITY[value] ?? value;
