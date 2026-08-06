# Post-v1 backlog

Explicitly deferred per remediation plan Phase 7. Do not implement as part
of v1 remediation. Each item requires a separate design decision or ADR.

## 7.1 Full liquidity semantics (RIEKO-AUDIT-011)

Remaining scope beyond v1:

- Channel reserves
- Pending HTLCs
- Commitment-fee effects
- Spendable liquidity
- Actual fee policy
- Operator-defined channel roles
- Routing-strategy context
- Node-wide liquidity objectives

Requires real-world evaluation data and a separate design decision.

## 7.2 Graph purpose decision (RIEKO-AUDIT-020)

Choose later between:

- Keeping the graph as a minimal protocol-neutral state store.
- Adding graph operations required by actual detectors.
- Renaming it if it remains a keyed state collection.

Do not add graph algorithms merely to justify the crate name.

## 7.3 Detector number two (drift detector)

The drift detector (`rieko-detectors/src/drift.rs`) remains experimental
until:

- The first liquidity slice satisfies all v1 gates.
- Historical persistence is trustworthy.
- Retention semantics are fixed.
- Stable finding identity exists.
- False-positive evaluation exists.

## 7.4 Simulation and execution

- Simulation: v2
- Approval and execution: v3

They require separate ADRs covering:

- Threat model
- Authentication and authorization
- Human approval workflow
- Exact action preview
- Simulation accuracy
- Rollback limitations
- Node permissions
- Audit guarantees
- Failure recovery
- Separate release features

Do not reactivate existing execution code (`LndExecutor`, `rieko-execution`,
`rieko-simulation`) merely because Phase 1 isolated it behind `#[cfg(feature = "future")]`.
