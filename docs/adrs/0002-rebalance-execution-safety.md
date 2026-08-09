# ADR-0002: Rebalance execution safety and rollback policy

- **Status:** Draft
- **Date:** 2026-08-06
- **Deciders:** Owner
- **Type:** Execution (v3, D7 Execute)

## Context

Phase 7.5 adds the `RebalanceChannel` action to the LND-backed executor.
Currently `LndExecutor` only supports `UpdateFeePolicy` (a single REST
call to `PUT /v1/chanpolicy`). A rebalance is fundamentally different:
it moves funds through a payment route, touching multiple channels and
incurring on-chain fees. The safety stakes are higher.

Rieko v1/v2 already provide the plumbing — simulation (Phase 7.4) projects
the effect of a rebalance on every channel in a route, and path-finding
(Phase 7.2) discovers the cheapest route through the channel graph.

This ADR defines the execution boundary for rebalancing: what we can safely
commit, what we cannot, and the rollback guarantees we provide (and do not
provide) to the operator.

The implementation is currently interlocked: even an `execute` feature build
refuses live execution. The route construction described by this draft has not
been validated against LND and none of its safety claims are release behavior.

## Decisions

### D1 — Rebalance via LND's `SendToRouteV2` (or `SendToRoute`)

Rieko calls LND's `POST /v2/router/send` (or `POST /v1/channels/transactions`
for the loop variant) with a pre-computed route. The route comes from the
graph's Dijkstra path-finder (Phase 7.2), and the amount is the simulated
delta (Phase 7.4).

We do **not** let LND choose the route — that would make the simulation
inaccurate and prevent per-hop projection.

### D2 — Single-hop only for v3

Multi-hop rebalances require atomic settlement across multiple channels. LND
does not offer a "rebalance atomically across N hops" API — each hop is a
separate payment. A cross-hop failure (e.g. hop 1 succeeds, hop 2 fails)
leaves the channel in an unintended state with no automated undo.

**v3 ships single-hop rebalancing only.** The operator rebalances one
channel at a time by moving funds to/from the peer via a circular route:
`self → peer → self` (a loop payment). This is the safest form of rebalance
and is path-independent (no multi-hop routing needed).

Multi-hop rebalance remains in the v3.1 backlog pending LND API support or
a multi-phase commit strategy.

### D3 — Pre-flight validation before every execution

Before calling LND, the executor validates:

1. **Channel exists** — the target channel is still in the graph.
2. **Channel is open** — `channel.status.is_open()`.
3. **Balance is sufficient** — `local_balance >= delta` on the source channel.
4. **Action is not stale** — the simulation was created within a configurable
   window (default: 5 minutes).

If any check fails, the execution is rejected with a clear error.

### D4 — Idempotency guard: one execution per action

Every executed action records an `execution_id` in the `audit` table with
a `stage = Executed` entry. Before executing, the executor checks whether
the action already has an `Executed` audit entry. If so, the execution is
skipped with a `"already executed"` message.

This prevents double-execution across restarts or operator mistakes.

### D5 — Rollback: intentional omission with documented limits

**Rollback is not supported for `RebalanceChannel`.** A rebalance payment
moves real funds. Once LND confirms the payment, the only way to reverse
it is another rebalance in the opposite direction, which incurs another
round of fees and may not be possible if liquidity has shifted.

What we **do** provide:
- Fee-policy rollback: `UpdateFeePolicy` stores the previous fee policy
  in the audit entry, so the operator can manually revert.
- Pre-execution state snapshot: the audit entry records the balance
  before execution.

What we **do not** provide:
- Automatic rebalance reversal.
- "Undo" button.

The operator makes an informed choice, with simulation preview and
pre-flight checks, and acknowledges that rebalances are one-way.

### D6 — Execution must remain gated behind `execute` and a runtime interlock

Execution code (`rieko-execution`, `LndExecutor`) remains behind
`#[cfg(feature = "execute")]`. The default binary cannot construct an LND
executor. Until this ADR is accepted and its regtest gates pass, the
execute-feature CLI must also refuse before constructing a live executor.

## Consequences

**Positive:**
- Single-hop rebalance is safe, deterministic, and path-independent.
- Pre-flight checks prevent stale or impossible executions.
- Idempotency guard prevents double-execution.
- Clear documentation of what we don't support (multi-hop, automatic rollback).

**Negative:**
- Single-hop only: operators with complex routing topologies may need
  multiple manual steps.
- No automatic rollback: operator bears the cost of mistaken rebalances.
- Gated behind `future` feature: not available to v1 default binary users.
