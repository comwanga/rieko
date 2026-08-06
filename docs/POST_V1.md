# Post-v1 Backlog — Implementation Plan

Explicitly deferred per remediation plan Phase 7. Each item requires a
separate ADR before implementation begins. The plans below are grounded in
the current codebase state.

---

## 7.1 Full Liquidity Semantics (RIEKO-AUDIT-011)

The v1 liquidity model uses `local_balance / capacity` for ratio only. The
full LND channel model has ~15 fields Rieko doesn't yet capture.

### 7.1.1 Extend `Channel` domain model

File: `crates/rieko-domain/src/channel.rs`

| New field | LND source | Why needed |
|-----------|-----------|------------|
| `channel_point: String` | `channel_point` | Required for per-channel fee policy targeting in the executor |
| `local_reserve_msat: u64` | `local_chan_reserve_sat * 1000` | Spending limit: `local_balance - local_reserve` |
| `remote_reserve_msat: u64` | `remote_chan_reserve_sat * 1000` | Receiving limit |
| `unsettled_msat: i64` | `unsettled_balance` | HTLCs in flight make snapshots stale |
| `pending_htlc_count: u32` | `len(pending_htlcs)` | Congestion signal |
| `total_sent_msat: u64` | `total_satoshis_sent * 1000` | Lifetime throughput for role detection |
| `total_received_msat: u64` | `total_satoshis_received * 1000` | Lifetime throughput |
| `is_private: bool` | `private` | Private channels have no forwarding demand |
| `is_initiator: bool` | `initiator` | Affects urgency of force-close risk |
| `lifetime_secs: u64` | `now() - channel_open_time` | New vs. mature channel |
| `uptime_secs: u64` | Tracked over cycles | Stability metric |

### 7.1.2 Extend `LiquidityProfile`

File: `crates/rieko-domain/src/channel.rs`

```rust
pub struct LiquidityProfile {
    // existing
    pub local_ratio: f64,
    pub local_balance_msat: u64,
    pub remote_balance_msat: u64,
    pub inbound_capacity_msat: u64,
    pub outbound_capacity_msat: u64,
    pub imbalance: LiquidityImbalance,
    // new
    pub spendable_outbound_msat: u64,  // local_balance - local_reserve
    pub spendable_inbound_msat: u64,   // remote_balance - remote_reserve
    pub pending_balance_delta_msat: i64, // unsettled effect
    pub throughput_direction: Option<ThroughputDirection>, // inbound/outbound/balanced
}
```

### 7.1.3 Add classification refinements

The current `LiquidityImbalance::compute()` thresholds (3%/10%/90%/97%) are
fixed. Add configurable thresholds per channel role:

- **Sink channel** (revenue, always inbound-heavy): `drain_threshold = 0.01`
- **Source channel** (outbound-only): `drain_threshold = 0.05`
- **Transit channel** (balanced): `drain_threshold = 0.10`

Operators define roles via config or heuristics (lifetime throughput ratio).

### 7.1.4 Add per-peer aggregation

File: `crates/rieko-detectors/src/liquidity.rs`

A new peer-level finding: "Peer X has N outbound-drained channels" when more
than half of a peer's channels are imbalanced.

### Dependencies

- Requires `rieko-domain` model changes first
- Requires `rieko-ingest-lnd/src/normalize.rs` to populate new fields
- Requires `rieko-ingest-lnd/src/model.rs` to deserialize new LND fields
- Requires migration to add columns to SQLite

---

## 7.2 Graph Purpose Decision (RIEKO-AUDIT-020)

Current state (`crates/rieko-graph/src/store.rs`): `InMemoryGraph` is a flat
key-value store — no adjacency index, no path-finding, no topology queries.
`channels_for_peer` is O(n).

### Option A: Keep as minimal state store (zero new code)

Keep the graph as an in-memory collection of channels/nodes with simple
lookups. Rename `rieko-graph` to `rieko-store-inmemory` or similar.

### Option B: Add lightweight topology (minimum viable graph)

1. **Add adjacency index** (`HashMap<NodeId, Vec<ChannelId>>`) at
   `store.rs:49`. `channels_for_peer` becomes O(1).
2. **Add Dijkstra shortest-path** for the rebalance simulation use case.
3. **Add connected-components** for "is this peer isolated?" queries.

### Option C: Full graph analytics (v2.5+)

Centrality metrics, bridge detection, community detection — only after
Option B proves the need.

### Recommendation

Start with **Option B** (adjacency + Dijkstra). The rebalance simulator
needs shortest-path to become useful. Crate name stays `rieko-graph`.

---

## 7.3 Detector #2 — Drift Detector

Current state (`crates/rieko-detectors/src/drift.rs`): computes trend
(`start_ratio - current_ratio`) over a window of 12 snapshots. Raises
Warning if decline ≥ 0.05, Critical if ≥ 0.15. But findings are never
persisted or recommended — the recommendation engine only dispatches on
`"channel_liquidity"`, not `"liquidity_trend"`.

### Phase 1: Make it ship-ready (no new features)

1. **Wire into pipeline**: Add `DriftDetector` to the detector registry at
   `crates/rieko-detectors/src/registry.rs` so it runs alongside
   `LiquidityDetector`.
2. **Add recommendation dispatch**: In `crates/rieko-recommendations/src/engine.rs`,
   add a match arm for `"liquidity_trend"` → produces a recommendation like
   "Inspect channel {id}: local ratio declined from {start} to {end} over
   {window} cycles. Confirm whether the decline is expected."
3. **Lifecycle tracking**: Use `FindingLifecycle` transitions (Active ↔
   Resolved) for drift findings. A finding with the same channel_id and
   declining trend should update rather than duplicate.
4. **Wire into CLI**: Once recommendations exist, `scan` and `monitor` will
   naturally include drift findings.

### Phase 2: Add rate-of-change metric

Change from absolute decline to per-cycle slope: `decline_ppm =
(decline / window) * 1e6`. This distinguishes "slow bleed over 100 cycles"
from "crash over 4 cycles."

### Phase 3: Per-channel thresholds

Allow operators to configure different `warn_decline` for different channels
(e.g., sink channels tolerate more decline than transit channels).

### Phase 4: Forwarding correlation

Cross-reference drift findings with forwarding events to detect cause:
"Channel is draining because outbound forwarding volume increased 3x."

### Dependencies

- Phase 1: none (drift detector already compiles and is tested)
- Phase 2: requires `ChannelSnapshot` timestamps in history window
- Phase 3: requires config system or channel-role metadata
- Phase 4: requires `ForwardEvent` ingestion (already working)

---

## 7.4 Simulation (v2)

Current state (`crates/rieko-simulation/src/lib.rs`):
- `RebalanceChannel` → projects ratio shift, checks if finding clears
- `UpdateFeePolicy` → no-op projection (fees don't move liquidity)
- `RestartService` / `Custom` → unsupported
- Single-channel only; no multi-hop routes

### Phase 1: Multi-hop rebalance simulation

1. **Add `Simulator::project_rebalance_route(channel, graph, target_ratio)`**
   that finds the cheapest route through the graph and projects the effect
   on every channel in the route.
2. Requires graph adjacency index + Dijkstra (7.2 Option B).
3. Output: `Simulation` gains a `route: Vec<(ChannelId, i64)>` field showing
   per-hop balance changes.

### Phase 2: Time-bound drift projection

`Simulator::project_drift(channel, snapshots, cycles_ahead)` — given
current drift rate, project what the ratio will be in N cycles. Used to
answer "will this channel be Critical in 24 hours?"

### Phase 3: Fee-policy simulation with forwarding impact

Replace the no-op `UpdateFeePolicy` simulation with one that estimates
forwarding volume change from historical forwards on the channel. Requires
per-channel forwarding history.

### Phase 4: Range simulation

Instead of a single `desired_ratio`, accept a range `[min, max, step]`.
Output a table of ratios and whether they clear the finding. The operator
picks the cheapest ratio that clears it.

### Phase 5: Graduate from `future` feature

Move `rieko-simulation` into the default build. Add a `/simulate` API
endpoint and a frontend simulation tab.

### Dependencies

- Phase 1: Graph adjacency + Dijkstra (7.2 Option B)
- Phase 2: Drift detector rate-of-change (7.3 Phase 2)
- Phase 3: Per-channel forwarding history in graph
- Phase 4: None (pure computation)
- Phase 5: API + frontend changes

---

## 7.5 Execution (v3)

Current state (`crates/rieko-execution/src/lnd.rs`):
- `UpdateFeePolicy` → works, calls `PUT /v1/chanpolicy`
- `RebalanceChannel` → returns `Unsupported` (the biggest gap)
- `RestartService` / `Custom` → unsupported
- State machine enforces human approval (`NeedsHuman` error)
- `RecordingExecutor` is a safe no-op default
- No idempotency guard, no rollback, no pre-flight checks

### Phase 1: Rebalance execution

1. **Implement `LndExecutor::execute_rebalance(action)`**:
   - Use graph's Dijkstra to find cheapest route
   - Call LND's `SendToRouteV2` or `SendPaymentV2` (via REST)
   - Set `amt` to the computed delta, set `last_hop_pubkey` to the peer
   - Return `ExecutionReport` with the payment hash

2. **Add idempotency guard**: Before executing, check if a
   `RebalanceChannel` action with the same params was already executed.
   Store `execution_id` + `payment_hash` in a new `executions` table.

3. **Add pre-flight validation**: Verify the channel still exists, is open,
   and the current balance matches the simulated projection assumptions.

### Phase 2: Multi-channel atomic execution

Actions that affect multiple channels (e.g., circular rebalance route)
must all succeed or all fail. Add a `BatchExecutor` that runs actions in a
group and rolls back if any fail.

### Phase 3: Rollback and undo

- Store pre-execution state (fee policy, balances) in the `executions` table
- Add `rollback` command that reverts the last fee policy update
- Rebalances cannot be rolled back (funds were moved); document this

### Phase 4: Approval UI

- Add frontend tab for pending approved actions
- Show simulation results before execution
- Require explicit human confirmation (click "Execute")

### Phase 5: Graduate from `future` feature

Move `rieko-execution` into an opt-in build feature (`--features execute`).
Add `actions approve` and `actions execute` CLI commands. Add API endpoints
for approval/execution workflows.

### Required ADRs

Before implementing any execution beyond `UpdateFeePolicy`, create separate
ADRs for:

- Rebalance execution safety and rollback policy
- Human-in-the-loop threat model
- Multi-signature or 2FA for execution
- Mainnet readiness checklist

---

## Summary

| Item | Prerequisite | Milestone |
|------|-------------|-----------|
| 7.1 Field extensions | None | v1.1 |
| 7.1 Per-peer aggregation | 7.1 field extensions | v1.1 |
| 7.1 Channel roles | Operator config system | v1.2 |
| 7.2 Graph adjacency | None | v1.1 |
| 7.2 Dijkstra path-finding | 7.2 adjacency | v1.1 |
| 7.3 Drift → shipped | None (detector compiles) | v1.1 |
| 7.3 Drift rate-of-change | 7.3 Phase 1 | v1.2 |
| 7.4 Multi-hop simulation | 7.2 Dijkstra | v2 |
| 7.4 Time-bound projection | 7.3 rate-of-change | v2 |
| 7.4 Range simulation | 7.4 Phase 1 | v2 |
| 7.5 Rebalance execution | 7.2 Dijkstra + 7.4 Phase 1 | v3 |
| 7.5 Rollback | 7.5 Phase 1 | v3 |
| 7.5 Approval UI | Frontend work | v3 |
