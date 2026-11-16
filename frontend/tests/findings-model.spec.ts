import { expect, test } from "@playwright/test";
import {
  actionabilityLabel, describeProvenance, evidenceValue, recommendationsFor, staleNote,
  type RecommendationDetail,
} from "../src/lib/findings";
import { parseLocation } from "../src/lib/router";

test.describe("stale findings", () => {
  const lastSeen = { relative: "3 hours ago", absolute: "2026-11-16 09:00:00 UTC" };

  test("only a finding the API reports as stale gets the tag and sentence", () => {
    expect(staleNote({ observation_stale: true }, lastSeen)).toEqual({
      tag: "Stale",
      detail: "Rieko last confirmed this finding 3 hours ago (2026-11-16 09:00:00 UTC) and has not confirmed it since. "
        + "It may no longer describe the current state.",
    });
    expect(staleNote({ observation_stale: false }, lastSeen)).toBeNull();
  });

  test("a response without the field, as an older agent sends, is not stale", () => {
    expect(staleNote({}, lastSeen)).toBeNull();
  });

  test("anything other than true is not trusted as stale", () => {
    for (const value of ["true", 1, null, {}]) {
      expect(staleNote({ observation_stale: value as unknown as boolean }, lastSeen)).toBeNull();
    }
  });

  test("the wording states the age of the last confirmation and asserts no cause or resolution", () => {
    const { detail } = staleNote({ observation_stale: true }, lastSeen)!;
    for (const claim of ["down", "unreachable", "offline", "disconnected", "resolved", "healthy", "fixed"]) {
      expect(detail.toLowerCase()).not.toContain(claim);
    }
  });
});

test.describe("routes", () => {
  test("finding detail carries its identifier", () => {
    expect(parseLocation("#/findings/finding-abc123")).toEqual({ id: "findings", param: "finding-abc123" });
    expect(parseLocation("#/findings/finding%2Fodd")).toEqual({ id: "findings", param: "finding/odd" });
    expect(parseLocation("#/findings")).toEqual({ id: "findings", param: null });
    expect(parseLocation("#/findings/")).toEqual({ id: "findings", param: null });
  });

  test("malformed identifiers, parameters on other views and unknown views are not trusted", () => {
    expect(parseLocation("#/findings/%E0%A4%A")).toEqual({ id: "findings", param: null });
    expect(parseLocation("#/overview/extra")).toEqual({ id: "overview", param: null });
    expect(parseLocation("#/nope/finding-abc")).toEqual({ id: "overview", param: null });
    for (const name of ["constructor", "__proto__", "toString"]) {
      expect(parseLocation(`#/${name}`)).toEqual({ id: "overview", param: null });
    }
  });

  test("the old Channels address opens Services", () => {
    expect(parseLocation("#/channels")).toEqual({ id: "services", param: null });
    expect(parseLocation("#/services")).toEqual({ id: "services", param: null });
  });
});

test.describe("evidence values", () => {
  test("scalars are shown as text and structures as formatted JSON", () => {
    expect(evidenceValue("outbound")).toEqual({ text: "outbound", block: false });
    expect(evidenceValue(0.08)).toEqual({ text: "0.08", block: false });
    expect(evidenceValue(false)).toEqual({ text: "false", block: false });
    expect(evidenceValue(null)).toEqual({ text: "null", block: false });
    expect(evidenceValue(["inv-1", "inv-2"])).toEqual({ text: JSON.stringify(["inv-1", "inv-2"], null, 2), block: true });
    expect(evidenceValue({ connected: true })).toEqual({ text: JSON.stringify({ connected: true }, null, 2), block: true });
  });
});

const snapshot = (observed_at: string, state_digest: string) => ({ network: "regtest", observed_at, state_digest });
const producers = [{ name: "channel_liquidity", version: "2", role: "detector" }];

test.describe("provenance", () => {
  test("missing provenance is reported as missing, not invented", () => {
    expect(describeProvenance(null)).toBeNull();
    expect(describeProvenance(undefined)).toBeNull();
  });

  test("fixture, LND and BTCPay sources show their redacted identity", () => {
    const fixture = describeProvenance({
      network: "regtest", source: { kind: "fixture", redacted_hash: "abc", configured_node: "local-node" }, producers,
      observation: { kind: "channel_state", channel_id: "c1", snapshot: snapshot("2026-11-14T10:00:00Z", "d1") },
    })!;
    expect(fixture.network).toBe("regtest");
    expect(fixture.source).toEqual([
      { label: "Source", value: "Fixture" }, { label: "Content hash", value: "abc" }, { label: "Configured node", value: "local-node" },
    ]);
    expect(fixture.producers).toEqual(producers);
    expect(fixture.observation).toEqual({
      kind: "Single observation", channel: "c1", snapshots: [snapshot("2026-11-14T10:00:00Z", "d1")],
    });

    const lnd = describeProvenance({
      source: { kind: "lnd", redacted_endpoint: "e1", configured_node: "02ab" }, producers: [],
      observation: { kind: "channel_window", channel_id: "c2", snapshots: [snapshot("t1", "a"), snapshot("t2", "b")] },
    })!;
    expect(lnd.network).toBeNull();
    expect(lnd.source).toEqual([
      { label: "Source", value: "LND" }, { label: "Endpoint (redacted)", value: "e1" }, { label: "Configured node", value: "02ab" },
    ]);
    expect(lnd.observation).toMatchObject({ kind: "Observation window", channel: "c2" });
    expect(lnd.observation.snapshots).toHaveLength(2);

    const btcpay = describeProvenance({
      source: { kind: "btc_pay", redacted_endpoint: "e2", configured_store: "store-1", underlying_node: "02cd" },
      producers: [], observation: { kind: "channel_state", channel_id: "c3", snapshot: snapshot("t", "d") },
    })!;
    expect(btcpay.source).toEqual([
      { label: "Source", value: "BTCPay Server" }, { label: "Endpoint (redacted)", value: "e2" },
      { label: "Configured store", value: "store-1" }, { label: "Underlying node", value: "02cd" },
    ]);
    const withoutNode = describeProvenance({
      source: { kind: "btc_pay", redacted_endpoint: "e2", configured_store: "store-1" },
      producers: [], observation: { kind: "channel_state", channel_id: "c3", snapshot: snapshot("t", "d") },
    })!;
    expect(withoutNode.source.map(row => row.label)).not.toContain("Underlying node");
  });

  test("an unrecognised source or observation is named, not guessed", () => {
    const view = describeProvenance({
      source: { kind: "something_new", detail: "x" }, producers: [], observation: { kind: "other", channel_id: "c4" },
    })!;
    expect(view.source).toEqual([{ label: "Source", value: "Unrecognised source (something_new)" }]);
    expect(view.observation).toEqual({ kind: "Unrecognised observation (other)", channel: "c4", snapshots: [] });
  });
});

test.describe("recommendations", () => {
  const rec = (finding_id: string, id: string): RecommendationDetail => ({
    finding_id,
    action: { id, action_type: "RebalanceChannel", stage: "Recommended", target: "c1", params: {}, summary: id, created_at: "t", updated_at: "t" },
    rationale: { evidence: [], preconditions: [], expected_effect: "", risks: [], limitations: [], actionability: "Informational" },
  });

  test("only the finding's own recommendations, in API order", () => {
    const all = [rec("f1", "a"), rec("f2", "b"), rec("f1", "c")];
    expect(recommendationsFor(all, "f1", 500)).toEqual({ items: [all[0], all[2]], possiblyIncomplete: false });
    expect(recommendationsFor(all, "f9", 500).items).toEqual([]);
  });

  test("a full page means the list may be incomplete", () => {
    const all = [rec("f1", "a"), rec("f2", "b")];
    expect(recommendationsFor(all, "f1", 2).possiblyIncomplete).toBe(true);
    expect(recommendationsFor(all, "f1", 3).possiblyIncomplete).toBe(false);
  });

  test("actionability labels", () => {
    expect(actionabilityLabel("Informational")).toBe("Informational");
    expect(actionabilityLabel("OperatorActionable")).toBe("Operator may choose to act");
    expect(actionabilityLabel("Unexpected")).toBe("Unexpected");
  });
});
