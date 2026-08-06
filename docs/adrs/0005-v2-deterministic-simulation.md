# ADR-0005: Rieko v2 — Deterministic Operational Simulation

- **Status:** Draft
- **Date:** 2026-08-07
- **Deciders:** Owner
- **Type:** Architecture (v2, D7 Simulate)

## Context

Rieko v1 already provides a `rieko-simulation` crate with pure projection
functions (`Simulator::project()`, `project_rebalance_route()`,
`project_drift()`). These functions are deterministic, snapshot-bound, and
read-only — they never contact LND or mutate state. However, they lack a
formal lifecycle, machine-readable assumptions/warnings, a confidence model,
and operator-facing CLI/API exposure (they sit behind the `future` feature
gate alongside execution code).

This ADR freezes the v2 simulation contract: the `SimulationRequest →
SimulationResult` lifecycle, the `SimulationModel` trait, the graduation
from `future` into a first-class `simulate` feature, and the invariant that
simulation never transitions into execution.

## Decisions

### D1 — Simulation is projection, not execution

A simulation produces a hypothetical `SimulationResult` and cannot trigger a
node action. The lifecycle stops at `Completed` (or `Stale`/`Failed`) — there
is no transition to `Approved` or `Executed`. The simulation crate must never
depend on `rieko-execution`.

### D2 — Models are deterministic and versioned

Identical input (channel snapshots, parameters, model ID + version) produces
identical output. Every simulation records `model_id`, `model_version`, and
an `input_hash` (SHA-256 of snapshot references + parameters + model identity)
so replay is independently verifiable.

### D3 — Every simulation is snapshot-bound

A simulation references immutable source data. The `source_snapshot_id` and
`source_observed_at` timestamp are recorded. Once created, the result is
never recomputed from newer data — it becomes `Stale` when the source data
ages past a configurable threshold.

### D4 — Unsupported actions fail closed

`SimulationModel::supports()` gates which recommendation types can be
simulated. Unknown or unsupported types return `SimulationStatus::Unsupported`
with no projection produced. No generic or guessed projection is generated.

### D5 — LLM is explanation-only

The LLM may explain a simulation result after the deterministic calculation
is complete. LLM output is stored as `explanation`, never as `result`. The
deterministic projection and its `input_hash` remain available when no LLM
is configured.

### D6 — V2 remains one binary and SQLite-first

No new production runtime — simulation is a crate (`rieko-simulation`)
compiled into the same Rust binary. Simulation results are stored in the
existing SQLite database via the `Storage` trait.

### D7 — Simulation state is separate from recommendation state

Creating a simulation does not modify the recommendation's `ActionStage`.
A simulation references a recommendation but does not prove or approve it.
The `has_simulations` flag on the recommendation is informational only.

### D8 — Simulation confidence is model-defined

Confidence is based on data completeness: `High` (all required fields
available), `Medium` (omits known local factors), `Low` (highly conditional),
`Unknown` (cannot be assessed). Confidence is never derived from severity,
LLM wording, or operator optimism.

### D9 — V2 simulation is default, not gated

The `simulate` feature is **enabled by default** in v2 (unlike v1's
`future` gate). The `execute` feature remains disabled-by-default and
pulls in `rieko-execution`. This split ensures the default binary can
simulate without being able to mutate.

### D10 — Stable assumption and warning codes

Assumptions and warnings carry stable string codes (e.g.
`RoutingPathNotValidated`, `FeesNotEstimated`) so operators and tooling
can programmatically identify them. Each code has a plain-language
description and a severity.

## Consequences

**Positive:**
- Simulation is deterministic, reproducible, and auditable.
- Operator can trace every result to source data.
- Unsupported actions are rejected honestly.
- Default binary supports simulation without execution capability.
- LLM independence preserved.

**Negative:**
- Staleness model adds complexity (source freshness must be tracked).
- Feature-gate split (`simulate` vs `execute`) requires updating all Cargo.toml
  files that currently use `future`.
- Existing `simulations` table must be migrated for new columns.
