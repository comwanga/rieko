import { expect, test } from "@playwright/test";
import type { Status } from "../src/lib/api";
import {
  btcpayCard, coreCard, findingsCount, formatTime, lightningCard, pipelineBadge, riekoCard,
  type BitcoinInspection, type BtcPayInspection, type CardModel, type LightningInspection,
} from "../src/lib/overview";

const NOW = new Date("2026-11-14T12:00:00Z");
const T = (secondsAgo: number) => new Date(NOW.getTime() - secondsAgo * 1000).toISOString();

const rows = (card: CardModel) => Object.fromEntries(card.rows.map(row => [row.label, row.value]));

const coreSnapshot = {
  network: "mainnet", block_height: 862341, header_height: 862341, synchronized: true, observed_at: T(30),
};
const lightningSnapshot = {
  node_id: "02abcdef", synced_to_chain: false, active_channels: 10, inactive_channels: 2, observed_at: T(45),
};

test.describe("service badges", () => {
  test("null state is not observed and renders no values", () => {
    for (const card of [coreCard({ state: null }, NOW), lightningCard({ state: null }, NOW)]) {
      expect(card.badge).toEqual({ kind: "neutral", label: "Not observed" });
      expect(card.rows).toEqual([]);
      expect(card.observed).toBeNull();
      expect(card.lastKnown).toBe(false);
    }
  });

  test("attempted but never successful is never connected, with the attempt time", () => {
    const card = coreCard({ state: { connected: false, last_attempt: T(5), last_success: null, snapshot: null } }, NOW);
    expect(card.badge).toEqual({ kind: "critical", label: "Never connected" });
    expect(card.rows).toEqual([]);
    expect(card.observed?.label).toBe("Last attempt");
    expect(card.observed?.relative).toBe("5 seconds ago");
  });

  test("connected Core shows only the fields the API returned", () => {
    const card = coreCard({ state: { connected: true, last_attempt: T(30), last_success: T(30), snapshot: coreSnapshot } }, NOW);
    expect(card.badge).toEqual({ kind: "ok", label: "Connected" });
    expect(rows(card)).toEqual({
      Network: "mainnet", "Block height": "862,341", "Header height": "862,341", Synchronized: "Yes",
    });
    expect(card.lastKnown).toBe(false);
    expect(card.observed).toMatchObject({ label: "Observed", relative: "30 seconds ago" });
    expect(card.attempt).toBeUndefined();
  });

  test("unsynchronized Core says No without asserting a cause", () => {
    const card = coreCard({ state: {
      connected: true, last_attempt: T(1), last_success: T(1),
      snapshot: { ...coreSnapshot, block_height: 862300, synchronized: false },
    } }, NOW);
    expect(rows(card).Synchronized).toBe("No");
    expect(rows(card)["Block height"]).toBe("862,300");
  });

  test("disconnected after success keeps last known values and says so", () => {
    const card = coreCard({ state: { connected: false, last_attempt: T(2), last_success: T(600), snapshot: coreSnapshot } }, NOW);
    expect(card.badge).toEqual({ kind: "critical", label: "Disconnected" });
    expect(card.lastKnown).toBe(true);
    expect(rows(card)["Block height"]).toBe("862,341");
    expect(card.observed).toMatchObject({ label: "Last observed", relative: "30 seconds ago" });
    expect(card.attempt?.relative).toBe("2 seconds ago");
  });

  test("LND shows node identity, sync and channel counts", () => {
    const card = lightningCard({ state: {
      connected: true, last_attempt: T(45), last_success: T(45), snapshot: lightningSnapshot,
    } } satisfies LightningInspection, NOW);
    expect(card.badge.label).toBe("Connected");
    expect(rows(card)).toEqual({
      "Node ID": "02abcdef", "Synced to chain": "No", "Active channels": "10", "Inactive channels": "2",
    });
    expect(card.rows.find(row => row.label === "Node ID")?.mono).toBe(true);
  });
});

test.describe("BTCPay card", () => {
  const greenfield = (connected: boolean, success: string | null): BtcPayInspection => ({ state: {
    source: { BtcPayGreenfield: { connected } }, last_attempt: T(3), last_success: success, source_data_at: success,
  } });

  test("a non-BTCPay source is not observed, even though state is present (M2b)", () => {
    for (const source of ["Fixture", { LndRest: { connected: true } }] as const) {
      const card = btcpayCard({ state: { source, last_attempt: T(3), last_success: T(3), source_data_at: T(3) } }, NOW);
      expect(card.badge).toEqual({ kind: "neutral", label: "Not observed" });
      expect(card.rows).toEqual([]);
    }
    expect(btcpayCard({ state: null }, NOW).badge.label).toBe("Not observed");
  });

  test("Greenfield connected, disconnected and never connected", () => {
    expect(btcpayCard(greenfield(true, T(3)), NOW).badge).toEqual({ kind: "ok", label: "Connected" });
    expect(btcpayCard(greenfield(false, T(120)), NOW).badge).toEqual({ kind: "critical", label: "Disconnected" });
    expect(btcpayCard(greenfield(false, null), NOW).badge).toEqual({ kind: "critical", label: "Never connected" });
  });

  test("rows are poll times only; no store row is invented", () => {
    const card = btcpayCard(greenfield(true, T(60)), NOW);
    expect(card.rows.map(row => row.label)).toEqual(["Last successful poll", "Last attempt", "Data as of"]);
    expect(rows(card)["Last successful poll"]).toContain("1 minute ago");
    expect(card.rows.some(row => /store/i.test(row.label))).toBe(false);
  });
});

test.describe("Rieko card", () => {
  const status = (overrides: Partial<Status> = {}): Status => ({
    engine: "rieko", version: "0.1.0", schema_version: 18, read_only: true, integrity: "ok", overall: "degraded",
    source: "fixture", source_data_at: T(100), last_ingestion: null, last_cycle: { attempt: T(10), success: T(10) },
    llm: "not_configured", alert_sink: "failing", cleanup: "healthy", last_cleanup: null,
    counts: {
      findings: 3, recommendations: 4, simulations: 2, audit: 4, channel_snapshots: 5,
      simulation_completed: 1, simulation_failed: 1, simulation_stale: 0,
    },
    ...overrides,
  });

  test("pipeline badge uses the backend state literally and never claims all systems", () => {
    expect(pipelineBadge("healthy")).toEqual({ kind: "ok", label: "Healthy" });
    expect(pipelineBadge("degraded")).toEqual({ kind: "warning", label: "Degraded" });
    expect(pipelineBadge("unhealthy")).toEqual({ kind: "critical", label: "Unhealthy" });
    expect(pipelineBadge("not_initialized")).toEqual({ kind: "neutral", label: "Not initialized" });
    expect(pipelineBadge("something_new")).toEqual({ kind: "neutral", label: "something_new" });
  });

  test("every previous Overview field is carried, as reported", () => {
    const card = riekoCard(status(), "2", NOW);
    // F3: the badge is labelled as the pipeline state, not the health of every system.
    expect(card.badge).toEqual({ kind: "warning", label: "Pipeline: Degraded" });
    expect(rows(card)).toMatchObject({
      Version: "v0.1.0", Schema: "18", "Database integrity": "ok", Build: "Read-only",
      "Active findings": "2", LLM: "Not configured", Alerts: "Failing", Cleanup: "Working",
    });
    expect(Object.fromEntries(card.records!.map(row => [row.label, row.value]))).toEqual({
      "Findings (all)": "3", Recommendations: "4", Simulations: "2 (completed 1, failed 1, stale 0)",
      "Snapshot rows": "5", "Audit entries": "4",
    });
    expect(card.observed).toMatchObject({ label: "Last detector cycle", relative: "10 seconds ago" });
  });

  test("channel data source appears only after a real ingestion (M2b)", () => {
    expect(rows(riekoCard(status(), "0", NOW))["Channel data source"]).toBeUndefined();
    const ingested = riekoCard(status({ last_ingestion: { attempt: T(9), success: T(9) } }), "0", NOW);
    expect(rows(ingested)["Channel data source"]).toBe("fixture");
  });

  test("absent values omit their rows", () => {
    const card = riekoCard(status({ last_cycle: null }), null, NOW);
    expect(rows(card)["Active findings"]).toBeUndefined();
    expect(card.observed).toBeNull();
  });
});

test.describe("formatting", () => {
  test("relative and absolute times", () => {
    expect(formatTime(T(0), NOW).relative).toBe("now");
    expect(formatTime(T(90), NOW).relative).toBe("2 minutes ago");
    expect(formatTime(T(7200), NOW).relative).toBe("2 hours ago");
    expect(formatTime(T(3 * 86400), NOW).relative).toBe("3 days ago");
    expect(formatTime(new Date(NOW.getTime() + 5000).toISOString(), NOW).relative).toBe("in 5 seconds");
    expect(formatTime(T(30), NOW).absolute).toBe(new Date(T(30)).toLocaleString());
  });

  test("a full page of findings is shown as a lower bound", () => {
    expect(findingsCount(0, 50)).toBe("0");
    expect(findingsCount(49, 50)).toBe("49");
    expect(findingsCount(50, 50)).toBe("50+");
  });
});

// Type-level check that the inspection types match the API's serialization.
const _bitcoin: BitcoinInspection = { state: null };
void _bitcoin;
