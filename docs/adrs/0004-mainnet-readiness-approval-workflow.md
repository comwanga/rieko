# ADR-0004: Mainnet readiness checklist and approval workflow

- **Status:** Draft
- **Date:** 2026-08-06
- **Deciders:** Owner
- **Type:** Operations / Execution (v3, D7 Execute)

## Context

Before any node-mutating action is sent to a mainnet LND node, the operator
must be able to verify that (a) Rieko is healthy, (b) the action is
appropriate, (c) the projected outcome is understood, and (d) there is a
recovery path if something goes wrong.

This ADR defines the approval workflow and the pre-execution checklist
the CLI enforces.

## Decisions

### D1 — Three-stage approval workflow

```
Scan → Detect → Recommend → Simulate → [Human reviews] → Approve → Execute
```

1. **Scan** — ingest, detect, recommend (existing).
2. **Simulate** — project the action's effect on every channel in the route
   (Phase 7.4, already built).
3. **Human reviews** — the operator examines the simulation output.
4. **Approve** — `rieko actions approve <action-id> --actor <name>`.
   Requires a non-empty, non-system actor string. The action enters
   `ActionStage::Approved`.
5. **Execute** — `rieko actions execute <action-id>`.
   Runs pre-flight checks, calls LND, records the audit entry.

### D2 — Pre-execution checklist (enforced by CLI)

Before `actions execute` proceeds, the CLI runs these checks in order:

1. **Action is Approved** — stage must be `ActionStage::Approved`.
2. **Simulation exists** — a `Simulation` record must reference this action.
3. **Simulation is recent** — created within the last 5 minutes (operator
   must re-simulate if the graph state may have changed).
4. **Channel is open** — the target channel `status.is_open()`.
5. **Balance is sufficient** — `local_balance >= delta` on the source.
6. **Not already executed** — no `Executed` audit entry for this action.

Any check failure aborts the execution with a clear message.

### D3 — Confirmation prompt (non-interactive flag available)

The CLI asks for explicit confirmation:
```
Channel  c1  0.10 → 0.50   40,000 msat
Execute this action on LND? [y/N]:
```

Pass `--yes` to skip the prompt (for scripts/automation — use with caution).

### D4 — Audit trail records everything

Every execution writes one audit entry:
```json
{
  "action_id": "<uuid>",
  "stage": "Executed",
  "actor": "alice",
  "details": {
    "channel": "c1",
    "delta_msat": 40000,
    "ratio_before": 0.10,
    "ratio_after": 0.50,
    "payment_hash": "<lnd-payment-hash>",
    "simulation_id": "<uuid>"
  }
}
```

The `details` JSON includes the payment hash from LND, so the operator can
cross-reference with `lncli listpayments`.

### D5 — Mainnet readiness gate

The `actions execute` command refuses to run unless **all** of the following
are true:

1. The `future` feature is enabled (compile-time gate).
2. Rieko is connected to a live LND node (not a fixture).
3. `--allow-mainnet` flag is explicitly passed.

Without `--allow-mainnet`, mainnet execution is refused:
```
Error: mainnet execution requires --allow-mainnet. Verify the read-only
observation pipeline first (see README#first-time-mainnet-validation).
```

### D6 — Fee-policy rollback via audit trail

`UpdateFeePolicy` stores the previous fee policy values in the audit entry.
The operator can manually revert by inspecting:
```sh
rieko audit --action-id <id>
```
and re-applying the previous values. No automated rollback command is
provided, but the audit trail gives the operator exactly what they need.

## Consequences

**Positive:**
- Every execution is checked, confirmed, and audited.
- Simulation preview is mandatory (no blind execution).
- Mainnet requires explicit opt-in (`--allow-mainnet`).
- Fee-policy changes are reversible via audit trail.

**Negative:**
- Rebalances are not reversible (LND payments are one-way).
- The confirmation prompt adds friction (acceptable for node operations).
- `--yes` flag exists but is documented as script-only.
