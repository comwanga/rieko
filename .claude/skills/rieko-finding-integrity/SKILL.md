---
name: rieko-finding-integrity
description: Use when adding, changing, reviewing, or debugging a Rieko detector, finding, correlation rule, finding lifecycle or resolution, evidence, provenance, explanation text, severity threshold, or recommendation - and when a finding is duplicated, never resolves, resolves too early, flaps, appears while a source is down, or its explanation says more than its evidence.
---

# Rieko finding integrity

A finding is a claim made to an operator about their Bitcoin infrastructure. It must be
reproducible from stored observations, and it must never say more than those
observations support.

## Four kinds of statement

Keep these apart in code, stored evidence, explanations, UI copy and your own reports.

| Kind | Meaning | Example in Rieko |
|---|---|---|
| Observed | A value a source returned, with the time it was seen | `block_height`, `synced_to_chain`, an invoice event |
| Derived | Computed deterministically from observed values | failure rate, `local_ratio`, a state digest |
| Inferred | A judgement that a condition exists; thresholds are heuristics | "Core is unsynchronized while BTCPay is reachable" |
| Proposed | A recommendation or a simulation of a hypothetical | a rebalance recommendation, a projection |

Evidence holds observed and derived values. The explanation states the inference in
plain words and may only summarise the evidence. An LLM explanation is optional and
must not add facts. Do not write causal language ("because", "caused by", "outage")
unless the evidence establishes the cause.

## The detector contract

Read `crates/rieko-detectors/src/registry.rs` before touching a detector.

- **Pure**: no I/O, no clock, no LLM, no mutation. Time comes from
  `DetectorContext::evaluated_at` or from timestamps in the observed state.
- **Identity**: `finding_identity(detector, version, network_scope, node, channel)`.
  `evaluate` rejects a finding whose id, detector, version, node or lifecycle disagree.
  The same condition must yield the same id on every cycle; replay yields no duplicates.
- **Version**: a version bump changes identity. Bump it when the judgement changes, and
  decide what happens to findings stored under the old version.
- **Completeness**: `is_complete` says whether this cycle saw enough to treat absence as
  evidence. When a required source is disconnected or has no snapshot, return no
  findings and report incomplete. Silence from an incomplete cycle resolves nothing.
- **Resolution**: storage resolves a finding only after consecutive complete cycles in
  which it was absent (`apply_finding_cycle` in `rieko-storage/src/sqlite.rs`; read the
  current count there). An incomplete cycle must not advance that count.
- **Scope**: lifecycle reconciliation is partitioned by `FindingCycleScope`
  (detector, network, node). A detector that returns `None` from `network_scope` is
  service-scoped; make sure a cycle cannot resolve findings outside its own scope.
- **Provenance**: source endpoints and identifiers are redacted before they enter the
  finding model.

## Checklist for a new or changed detector

1. State the condition in one sentence using only observed and derived terms.
2. List each source it needs. What does the detector do when each is disconnected,
   never connected, or connected with no snapshot?
3. Where does the finding's timestamp come from? It should be the observation time.
4. Are thresholds named, documented as heuristics, and present in the evidence so an
   operator can see why the severity was chosen?
5. Does the evidence contain every value the explanation mentions?
6. Does a severity change keep the same identity? Alert cooldown is pierced by an
   escalation to Critical; check `rieko-alerts` if severity logic changes.
7. If the detector consumes events, are duplicates and out-of-order arrival handled, and
   is each logical item counted once? `docs/settlement-reliability.md` is the model.

## Tests a detector needs

Follow the existing files (`bitcoin_core_sync_correlation.rs` is the smallest example):

- emits one finding with exact evidence for the triggering state;
- emits nothing, with a complete cycle, for the healthy state;
- emits nothing, with an incomplete cycle, for each unavailable-source state;
- deduplicates across repeated cycles and resolves through hysteresis, at the agent
  level (`rieko-cli/src/agent.rs` tests named `*_deduplicate_and_resolve_*`);
- boundary values for each threshold.

## Reviewing an existing finding or incident

Start from the stored row (`rieko explain <finding-id>`, or `GET /findings/:id`), not
from the explanation text. For each claim, find the evidence key that supports it. Report
claims with no supporting evidence as defects in the detector, and separate what the
stored data shows from what you infer about the operator's system.
