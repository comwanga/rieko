# ADR-0003: Human-in-the-loop threat model for execution

- **Status:** Draft
- **Date:** 2026-08-06
- **Deciders:** Owner
- **Type:** Security / Execution (v3, D7 Execute)

## Context

Rieko v3 introduces the ability to mutate a live LND node via the execution
trait (`Executor::execute`). The engine can now move funds (rebalance) and
change fee policies (update_chan_policy). Without a clear human-in-the-loop
model, an attacker or a bug could drain channels or disrupt routing.

Current implementation status: live execution is interlocked and unsupported.
The decisions below are proposed release requirements, not implemented claims.

The existing state machine already enforces that the system actor
(`"system"`) cannot self-approve — approval requires a non-empty, non-system
actor string. This ADR extends that model to the execution surface.

## Decisions

### D1 — Two-person-rule is out of scope

A true two-person-rule (2-of-n multi-sig) requires a separate signing device
and an out-of-band verification step. For a single-operator tool, this adds
complexity without proportional benefit: the operator already controls both
the machine Rieko runs on and the LND node.

**v3 uses single-operator approval.** The operator who runs Rieko is the
same person who holds the LND wallet. Adding a second approver would not
add meaningful security — it would just move the trust boundary.

Multi-sig / 2FA approval remains a v3.1 consideration only if Rieko is
ever deployed in a multi-operator or custodial context.

### D2 — Actor identity is recorded, not authenticated

The `actor` field on audit entries is a free-form string (e.g. `"alice"`).
It is recorded for audit trail purposes but **not cryptographically verified**.
An attacker with shell access to the Rieko host can forge the actor string.

This is acceptable for v3 because:
- Rieko runs on the operator's own hardware, behind loopback by default.
- The execution CLI is only reachable via the `future` feature.
- The operator is the only user.

If Rieko is ever exposed over a network (non-loopback), the actor string
alone is insufficient — external access must require a bearer token
(RIEKO-AUDIT-014) and execution must be disabled for external callers.

### D3 — Execution is CLI-only, not API-exposed

The `actions execute` CLI command is the only path to trigger execution.
The read-only API (`rieko-api`) never exposes execution endpoints — even
when the `future` feature is enabled. This keeps the execution surface
minimal and local-only.

### D4 — No blind execution: simulation preview required

Every `actions execute` command must reference an action that has been
simulated (has a `Simulation` record). If no simulation exists, execution
is rejected. The operator must see the projected outcome before committing.

The CLI prints the simulation summary and asks for confirmation before
calling LND:
```
Simulation projects 40,000 msat moved. Channel c1 goes from 0.10 to 0.50 ratio.
Execute? [y/N]:
```

### D5 — Execution is synchronous and blocking

Executing a rebalance payment may take seconds (LND route finding + payment
confirmation). The executor blocks until LND returns success or failure —
there is no async execution, no background job, and no queue. If the CLI
process is killed mid-execution, LND may still complete the payment
(independently of Rieko). This is documented in the operator guide.

### D6 — Secrets are never stored in audit entries

The macaroon hex, TLS cert path, and LND REST URL are never written to the
audit log, findings, or execution reports. Only the action identity, actor,
stage transition, and a human-readable detail string are persisted.

## Consequences

**Positive:**
- Execution surface is minimal (CLI-only, single hop, local-only).
- Every execution requires simulation preview and explicit confirmation.
- Actor identity is auditable without adding a user-management system.

**Negative:**
- No multi-sig/2FA: single-operator trust model only.
- Actor string is not cryptographically verified.
- External Rieko exposure requires bearer token but execution remains
  a risk if API is exposed.
