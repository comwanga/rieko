# Rieko v1 — Phase-by-Phase Remediation and Implementation Plan

Repository:

`https://github.com/comwanga/rieko.git`

Authoritative architecture contract:

`docs/adrs/0001-rieko-v1-architecture.md`

Authoritative audit:

`Rieko — Architecture, Security and Production-Readiness Audit`, dated `2026-08-05`

Audited repository state:

* Branch: `lnd-executor`
* Audited commit: `13089a3`
* Current maturity: early prototype / demo vertical slice
* Current release verdict: stop and harden
* Current permitted environment: fixture-only development
* Real LND/mainnet connection: prohibited until Phase 1 is complete

## Mission

Implement the audit remediation plan in strict dependency order and produce a trustworthy Rieko v1 alpha that:

* Observes LND safely.
* Normalizes data into protocol-neutral domain objects.
* Detects channel liquidity conditions deterministically.
* Produces stable typed findings.
* Produces conservative recommendations backed by evidence.
* Optionally explains findings using an LLM.
* Sends deduplicated alerts.
* Persists state safely in SQLite.
* Exposes meaningful operational status.
* Ships as one self-contained Rust binary.
* Cannot mutate LND or Bitcoin Core state.

Rieko v1 ends at:

`Observe → Explain → Recommend`

Rieko v1 must not reach:

`Simulate → Approve → Execute`

The presence of future-facing types or interfaces must not make those capabilities reachable from the v1 CLI, API, frontend or release binary.

---

# 1. Non-negotiable implementation rules

## 1.1 Evidence before modification

Before changing a work package:

1. Inspect the files cited by the audit.
2. Confirm that the reported behaviour still exists in the current branch.
3. Record any repository changes made after commit `13089a3`.
4. Do not blindly implement a recommendation if the current code has already changed.
5. Do not create a new finding unless supported by exact repository evidence.
6. Do not silently reinterpret ADR-0001.

When the repository differs from the audited state:

* Describe the difference.
* Determine whether the audit finding remains open, partially resolved or resolved.
* Adjust only the affected implementation steps.
* Do not discard the rest of the approved plan.

## 1.2 No scope expansion

Do not add:

* Microservices.
* Redis.
* Kafka.
* PostgreSQL.
* DuckDB.
* Kubernetes.
* A Python production service.
* A Node.js production service.
* Autonomous remediation.
* Machine-learning detectors.
* Multiple-node orchestration.
* Cloud control planes.
* Proof-of-reserves.
* Compliance reporting.
* CVE intelligence.
* Additional detector families.
* Advanced graph analytics.
* New execution capabilities.

Do not replace SQLite.

Do not introduce abstractions for hypothetical future backends unless required by an existing v1 interface.

Do not redesign the whole project when a local correction is sufficient.

## 1.3 No broad refactoring

Refactor only when required to:

* Enforce the read-only boundary.
* Implement deterministic identity and persistence.
* Add storage transactions and migrations.
* Persist alert state.
* Implement meaningful operational status.
* Correct an audited security or correctness defect.
* Make a release artifact genuinely self-contained.

Avoid:

* Renaming unrelated modules.
* Reformatting unrelated files.
* Rewriting working crates.
* Moving files without functional need.
* Adding generic frameworks.
* Creating abstractions with only one speculative implementation.
* Changing public APIs unrelated to the active work package.

## 1.4 One work package at a time

For each work package:

1. Inspect.
2. Write or update tests that demonstrate the defect.
3. Implement the smallest correction.
4. Run targeted tests.
5. Run workspace checks.
6. Document what changed.
7. Stop before starting the next package unless explicitly instructed to continue.

Do not combine unrelated findings into one large change.

## 1.5 Definition of complete

A work package is not complete because it compiles.

Completion requires:

* The affected audit finding is demonstrably resolved.
* Required regression tests exist.
* Existing tests remain green.
* Documentation matches actual behaviour.
* No new v1 scope is introduced.
* Acceptance criteria are satisfied with command output or test evidence.
* Any remaining limitation is stated explicitly.

---

# 2. Permanent v1 invariants

These invariants must hold after every phase.

1. The shipped v1 binary cannot spend funds.
2. The shipped v1 binary cannot open, close or rebalance channels.
3. The shipped v1 binary cannot update channel fee policy.
4. The shipped v1 binary cannot mutate Bitcoin Core.
5. LLM output cannot create, suppress, elevate or modify deterministic findings.
6. Rieko remains functional when the LLM is unavailable.
7. Replaying identical source data does not create duplicate operational records.
8. Restarting Rieko does not reset alert cooldown state.
9. `/status` does not report healthy solely because the HTTP server is running.
10. Secrets never appear in logs, findings, audit entries or API responses.
11. Findings preserve their detector identity, detector version and evidence.
12. Future simulation or execution code cannot become reachable accidentally.
13. Rieko binds to loopback by default.
14. A normal v1 build requires one Rust runtime and one SQLite database.
15. Node access uses the minimum permissions required for observation.

Add regression coverage for these invariants where practical.

---

# 3. Delivery structure

Implement the remediation in these phases:

* Phase 0 — Establish the verified baseline.
* Phase 1 — Enforce v1 safety and deterministic persistence.
* Phase 2 — Make SQLite and state transitions dependable.
* Phase 3 — Complete the trustworthy v1 vertical slice.
* Phase 4 — Harden operator-facing interfaces.
* Phase 5 — Deliver the single-binary release and CI gates.
* Phase 6 — Validate controlled LND integration.
* Phase 7 — Post-v1 backlog only.

Phases 0–1 block any real-node connection.

Phases 0–3 block `v0.1.0-alpha`.

Phases 4–6 block external operator testing.

Phase 7 must not be implemented as part of the v1 remediation unless separately approved.

---

# Phase 0 — Establish the verified baseline

## Objective

Create a reproducible pre-change baseline and prevent implementation against stale audit assumptions.

## Scope

Inspect:

* Current branch and commit.
* Workspace members.
* Existing Cargo features.
* CLI subcommands.
* API routes.
* Frontend routes and navigation.
* SQLite schema.
* Existing tests.
* Existing CI.
* README and ADR-0001.
* All files cited by audit findings `RIEKO-AUDIT-001` through `022`.

## Required actions

### 0.1 Confirm repository state

Record:

```text
Current branch:
Current commit:
Audited branch:
Audited commit:
Commits since audit:
Files changed since audit:
Audit findings already affected:
```

Do not reset or overwrite user work.

### 0.2 Reproduce the baseline

Run:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo tree --workspace
cargo tree --workspace --duplicates
```

Run dependency checks only when installed:

```bash
cargo deny check advisories
cargo deny check bans
cargo deny check licenses
cargo audit
```

An unavailable tool must be reported as unavailable, not described as passing.

Inspect the frontend package manager before running frontend commands. Run only scripts defined in `frontend/package.json`.

### 0.3 Reproduce the critical defects safely

Use fixtures and throwaway databases only.

Verify, without touching a real node:

* Exact fixture replay creates duplicate rows.
* `actions execute` is reachable.
* Simulation re-runs and duplicates the pipeline.
* Alert deduplication is memory-only.
* `/status` reports only counts and contains a hardcoded read-only claim.
* The frontend requires an external `dist` directory.
* The LND macaroon is read as text.
* No TLS certificate option exists for LND’s self-signed certificate.

Do not send any request to a real LND node.

## Deliverable

Create a short baseline report containing:

* Confirmed open findings.
* Findings already resolved.
* Findings whose implementation differs from the audit.
* Exact test results.
* Approved starting point for Phase 1.

## Acceptance criteria

* The current repository state is documented.
* Every P0 audit claim is confirmed or corrected.
* Existing tests pass, or failures are recorded without being hidden.
* No production code is changed during baseline verification.

---

# Phase 1 — Enforce v1 safety and deterministic persistence

This phase contains the four P0 blockers.

No real LND, regtest LND or mainnet node may be connected until the whole phase passes.

---

## Work Package 1.1 — Remove node mutation from the v1 product

### Audit findings

* `RIEKO-AUDIT-001`
* `RIEKO-AUDIT-015`
* Scope consequences from `RIEKO-AUDIT-022`

### Objective

Ensure that no v1 CLI, API, frontend or default release build can perform an LND mutation.

### Inspect first

At minimum inspect:

* `crates/rieko-cli/src/commands/actions.rs`
* `crates/rieko-execution/src/lnd.rs`
* `crates/rieko-execution/src/lib.rs`
* `crates/rieko-ingest-lnd/src/client.rs`
* Workspace and crate `Cargo.toml` files
* CLI command registration
* API routes
* Frontend routes, navigation and action controls
* README examples

### Required v1 behaviour

The normal v1 build must not expose:

* `actions execute`
* Any live `LndExecutor`
* `update_chan_policy`
* Any LND REST mutation
* Any Bitcoin Core mutation
* Approval interfaces that imply executable authority
* An actor string pretending to represent authenticated human approval

### Preferred minimal implementation

Use the smallest clean approach supported by the current codebase:

1. Keep domain enums and transition types only where required by the action-model contract.
2. Remove the live LND executor from the normal v1 dependency graph.
3. Remove or disable CLI execution registration.
4. Remove execution controls from the frontend.
5. Remove any execution-related API exposure.
6. Do not document a hidden command as part of v1.

A future-only Cargo feature is acceptable only when:

* It is disabled by default.
* It is not enabled by any v1 build or CI release job.
* The normal `rieko` CLI cannot expose execution.
* The feature is explicitly marked unsupported and post-v1.
* Tests prove the default build remains read-only.

Do not retain an environment-variable switch that can activate mutation in the same v1 binary. That would not satisfy the read-only boundary.

### Simulation boundary

For v1, choose the least risky option:

* Keep simulation projection types as an isolated library interface.
* Make the simulation CLI/API/frontend unreachable in the default v1 product.

Do not redesign simulation in this package. Its data correctness is handled later only if simulation remains in the repository as a future interface.

### Required tests

Add tests proving:

* Default CLI help does not advertise executable mutation.
* Calling an unavailable execution command fails without touching a network.
* Default workspace/release features do not enable a live executor.
* No v1 API mutation route exists.
* No frontend control offers approval or execution.
* Pure action transition tests can remain if they do not create reachability.

Do not rely only on a grep test. Prefer compile-time dependency isolation and CLI integration tests. A source scan may be an additional guard.

### Completion evidence

Report:

* Removed or gated entry points.
* Default feature graph.
* CLI help output.
* API route inventory.
* Relevant tests.
* Confirmation that the normal release binary cannot construct `LndExecutor`.

### Acceptance criteria

* The default v1 binary cannot mutate LND or Bitcoin Core.
* No hidden runtime flag can turn mutation on.
* No operator-facing v1 interface claims execution capability.
* The read-only guarantee is enforced structurally, not merely documented.

---

## Work Package 1.2 — Implement stable finding identity and idempotent persistence

### Audit findings

* `RIEKO-AUDIT-002`
* Relevant parts of `RIEKO-AUDIT-012`
* Replay implications from `RIEKO-AUDIT-022`

### Objective

Ensure that replaying identical observations produces no duplicate findings, recommendations or audit records.

### Inspect first

At minimum inspect:

* `crates/rieko-findings/src/finding.rs`
* `crates/rieko-findings/src/action.rs`
* `crates/rieko-detectors/src/liquidity.rs`
* `crates/rieko-detectors/src/drift.rs`
* `crates/rieko-storage/src/sqlite.rs`
* Storage trait definitions
* `crates/rieko-cli/src/commands/common.rs`
* `scan`
* `monitor`
* `simulate`
* Source ledger implementation and current call sites

### Identity rules

Create deterministic identity from evidence that represents the same operational occurrence.

The implementation must define, document and test:

* Detector identifier.
* Detector version.
* Entity identifier.
* Finding kind.
* Observation or evaluation window.
* Canonical evidence representation.
* Deduplication key.
* Stable persisted identity.

Do not use a random UUID as the only persistence identity.

A random event ID may remain as metadata only if persistence uniqueness is enforced using a deterministic key.

### Canonicalization requirements

The identity input must be deterministic:

* Sort evidence fields where order is not semantically meaningful.
* Do not include `Utc::now()` unless time is genuinely part of the observation window.
* Do not hash arbitrary debug output.
* Do not include an LLM explanation.
* Do not include transient database row IDs.
* Do not include fields that change merely because the same data was processed again.

Use a standard cryptographic hash already appropriate for Rust. Do not introduce a custom hash algorithm.

### Persistence behaviour

Implement database uniqueness for the deterministic identity.

Required behaviour:

* First observation inserts the finding.
* Exact replay does not create another finding.
* Existing finding may update safe mutable fields such as `last_seen_at`.
* Exact replay does not create duplicate recommendations.
* Exact replay does not append a false audit transition.
* LLM explanation updates the existing finding instead of inserting another finding.
* A materially changed observation may create a new occurrence or update lifecycle state according to the defined model.
* Recommendation identity is derived from its source finding and action type, not from a fresh random ID alone.

### Source ledger

Use the existing source ledger only where its semantics are clear.

Define:

* Source identifier.
* Last successfully processed cursor, event or observation time.
* When the ledger advances.
* Behaviour on transaction failure.
* Behaviour on replay.
* Behaviour on an older observation.
* Behaviour when no reliable source cursor exists.

Do not make the fixture file’s wall-clock processing time the source cursor.

The source ledger must complement deterministic persistence; it must not be the only duplicate defence.

### Required integration tests

At minimum:

1. Run `scan` against a clean DB.
2. Record all row counts.
3. Run the exact same scan against the same DB.
4. Assert:

   * No additional findings.
   * No additional recommendations.
   * No additional transition audit entries.
   * No duplicate snapshots for the same logical observation, where applicable.
5. Modify one meaningful input field.
6. Assert exactly the expected state change occurs.
7. Restart and replay.
8. Assert idempotency remains intact.

Add tests for deterministic identity across process runs.

### Acceptance criteria

* Exact replay creates zero duplicate operational records.
* Finding identity is stable and documented.
* Recommendation identity is stable.
* Source ledger is actively used or explicitly removed if unnecessary.
* The LLM cannot influence identity.
* Existing fixture scans remain deterministic.

---

## Work Package 1.3 — Correct LND authentication, TLS and least-privilege access

### Audit finding

* `RIEKO-AUDIT-003`

### Objective

Make the live LND observation path technically correct and safe enough for later controlled testing.

Do not connect to a real node during implementation.

### Inspect first

At minimum:

* LND REST client.
* CLI macaroon loading.
* URL parsing.
* Reqwest client construction.
* README live-node command.
* Current TLS and authentication tests.
* Actual LND endpoints called by Rieko v1.

### Macaroon handling

Required behaviour:

* Read macaroon bytes with a binary-safe API.
* Encode the bytes as lowercase hexadecimal for the `Grpc-Metadata-macaroon` header.
* Do not treat a binary macaroon as UTF-8.
* Never log the macaroon.
* Never include it in an error message.
* Avoid command-line secret values where the process list could expose them.
* Continue accepting a file path rather than raw secret contents.

### TLS handling

Add explicit support for LND’s TLS certificate.

Preferred interface:

```text
--tls-cert <path>
```

Required behaviour:

* Read the configured certificate.
* Add it as a trusted root for the specific client.
* Preserve normal certificate validation.
* Preserve hostname validation.
* Do not globally disable certificate validation.
* Do not add `danger_accept_invalid_certs(true)`.
* Produce a clear error when the certificate is absent or invalid.

Do not silently downgrade HTTPS to HTTP.

### Least-privilege access

Determine required permissions from the exact read-only endpoints currently called.

Document only permissions supported by evidence from the implementation.

Do not guess a permission list.

The documentation must:

* Stop recommending `admin.macaroon`.
* State that Rieko v1 is read-only.
* Explain that a restricted macaroon should be created for only the required read operations.
* List the precise RPC permissions after verifying them against the actual client methods.
* Warn that an admin macaroon is unnecessary and unsafe.

### Required tests

Use mocks or local test servers.

Test:

* Header equals hex-encoded file bytes.
* Binary bytes that are invalid UTF-8 still work.
* Missing macaroon file fails cleanly.
* Secret is absent from errors.
* Untrusted self-signed TLS server is rejected.
* The same server is accepted when the exact certificate is configured.
* Wrong certificate is rejected.
* Mutation methods are absent from the v1 client interface.

### Acceptance criteria

* Authentication header is correct.
* TLS works without disabling verification.
* No admin macaroon appears in normal documentation.
* The client exposes only methods needed for observation.
* Tests run without a real node.

---

## Work Package 1.4 — Persist alert deduplication and cooldown

### Audit finding

* `RIEKO-AUDIT-004`

### Objective

Ensure restart or process failure does not reset alert cooldown or severity state.

### Inspect first

At minimum:

* `crates/rieko-alerts/src/dedup.rs`
* Telegram sink
* Storage trait
* SQLite schema
* Monitor setup
* Finding deduplication key
* Current in-memory severity tracking

### Data model

Persist only the minimum necessary alert state:

* Alert deduplication key.
* Destination or sink identity where needed.
* Last successful send timestamp.
* Last sent severity.
* Cooldown duration or applicable policy version if necessary.
* Latest delivery status where useful.

Do not create a general-purpose messaging queue in v1.

### Behaviour

Required:

* Load persisted state when monitor starts.
* Suppress the same alert within cooldown after restart.
* Re-alert after cooldown expires.
* Permit immediate alert when severity increases according to an explicit rule.
* Permit future alert after the underlying finding resolves and recurs.
* Update `last_sent_at` only after successful delivery.
* A failed Telegram request must not falsely consume the cooldown.
* Time comparisons must use persisted UTC timestamps, not `Instant`, across restarts.

### Required tests

1. Send alert successfully.
2. Recreate the sink/process state.
3. Attempt the same alert inside cooldown.
4. Assert suppression.
5. Advance test clock beyond cooldown.
6. Assert delivery.
7. Increase severity within cooldown.
8. Assert defined escalation behaviour.
9. Simulate failed delivery.
10. Assert cooldown was not consumed.

Use a controllable clock abstraction only if needed for deterministic tests. Keep it narrow.

### Acceptance criteria

* Cooldown survives restart.
* Severity state survives restart.
* Failed sends do not masquerade as successful alerts.
* No Redis, broker or background queue is introduced.

---

## Phase 1 release gate

Phase 1 passes only when all are true:

* Default v1 cannot execute node mutations.
* Exact fixture replay creates no duplicate findings, recommendations or audit entries.
* Macaroon bytes are correctly hex encoded.
* LND TLS certificate pinning is implemented.
* Documentation no longer recommends `admin.macaroon`.
* Alert cooldown survives restart.
* All workspace tests and quality checks pass.

After Phase 1, controlled regtest preparation may begin. Mainnet remains prohibited until Phases 2–4 pass.

---

# Phase 2 — Make SQLite and state transitions dependable

---

## Work Package 2.1 — Introduce versioned migrations

### Audit finding

* `RIEKO-AUDIT-005`

### Objective

Make schema upgrades explicit, ordered, testable and safely reject unsupported databases.

### Constraints

Use SQLite’s built-in schema version capability or a small project-owned migration table.

Do not introduce a migration framework unless the existing code clearly benefits from it.

Prefer the smallest transparent implementation.

### Required design

Define:

* Current schema version.
* Ordered migration steps.
* Transactional migration execution.
* Behaviour for a fresh database.
* Behaviour for the immediately previous supported version.
* Behaviour for a newer unsupported schema.
* Behaviour after a failed migration.
* Backup expectations in operator documentation.

Required rules:

* Fresh database reaches the latest schema.
* Migration is idempotent after completion.
* Unknown newer versions are rejected.
* A failed migration does not leave a falsely advanced version.
* Existing data is preserved.
* Schema version is visible through status or diagnostic output.

### Required tests

* Empty DB to current schema.
* Current schema reopened.
* Previous schema migrated with seeded data preserved.
* Unsupported newer schema rejected.
* Deliberately failing migration rolls back.
* Partially initialized DB handled explicitly.

### Acceptance criteria

* Schema version is stored.
* Migration order is deterministic.
* CI runs migration tests.
* Upgrade behaviour is documented.

---

## Work Package 2.2 — Correct SQLite operational settings and transactions

### Audit finding

* `RIEKO-AUDIT-006`

### Objective

Prevent avoidable lock failures and partial scan-cycle persistence.

### Required connection settings

Verify and explicitly set:

* WAL mode.
* Foreign keys enabled.
* Busy timeout of a justified finite duration.
* Synchronous mode selected and documented.
* Connection error context.
* Read/write expectations.

Do not tune SQLite using arbitrary performance settings.

### Transaction boundaries

Persist one logical processing unit atomically.

A detector cycle that creates or updates:

* Findings.
* Recommendations.
* Explanations.
* Audit transitions.
* Source ledger.
* Related metadata.

must either commit as one coherent state or roll back.

Snapshots may use a separate defined transaction if necessary, but their boundary must be explicit.

### Concurrency

Support the actual deployment pattern:

* One monitor process writing.
* One API process or server path reading.
* SQLite WAL.
* No assumption of unlimited concurrent writers.

Prevent or clearly reject multiple monitor writers when they would corrupt operational semantics.

Do not add a distributed lock service.

A simple local process lock or database ownership rule may be used if justified.

### Integrity handling

Add a diagnostic path for:

* `PRAGMA quick_check` or equivalent.
* Reporting database integrity failure.
* Refusing to claim healthy when integrity checks fail.

Do not automatically delete or recreate a corrupt production database.

### Required tests

* Reader and writer operating concurrently.
* Two attempted writers.
* Busy timeout behaviour.
* Failure halfway through cycle persistence.
* Confirm rollback leaves no half-written recommendation/audit state.
* Integrity check success.
* Corrupt DB produces a clear error.

### Acceptance criteria

* A cycle is atomic.
* Concurrent expected usage does not immediately fail with `SQLITE_BUSY`.
* Partial records are not committed after simulated failure.
* Corruption is reported, never silently discarded.

---

## Work Package 2.3 — Stabilize findings and lifecycle metadata

### Audit finding

* `RIEKO-AUDIT-012`

### Objective

Make findings traceable, versioned and safe to reload.

### Minimum fields

Add only what v1 requires:

* Finding schema version.
* Detector ID.
* Detector version.
* Stable dedup identity.
* Entity ID.
* Observation start/end or evaluation timestamp.
* First seen timestamp.
* Last seen timestamp.
* Severity.
* Evidence.
* Lifecycle state sufficient to distinguish active and resolved.
* Optional confidence only when the detector has a defensible meaning for it.

Do not create a complex incident-management workflow.

### Lifecycle

At minimum define:

* Active.
* Resolved.

Recurrence semantics must be explicit:

* Same condition while active updates `last_seen_at`.
* Absence during a defined later evaluation may resolve it.
* Recurrence after resolution is either reopened or represented as a new occurrence according to one documented rule.

Do not infer resolution merely because one scan failed.

### Strict decoding

Remove silent fallback behaviour that:

* Converts malformed evidence into an empty list.
* Replaces invalid timestamps with `Utc::now()`.

Corrupt persisted data must produce a typed error.

### Required tests

* Same detector/input produces same identity.
* Changed detector version is distinguishable.
* Active finding updates `last_seen_at`.
* Resolved finding retains original evidence history required by the model.
* Malformed evidence fails loudly.
* Malformed timestamp fails loudly.
* Older schema rows migrate correctly.

### Acceptance criteria

* Findings are independently explainable.
* Detector version is preserved.
* Corrupt rows cannot silently become valid-looking findings.
* Lifecycle does not depend on LLM text.

---

## Work Package 2.4 — Align audit entries with real state transitions

### Audit finding

* `RIEKO-AUDIT-007`

### Objective

Ensure the audit trail never claims a transition that did not occur.

### Scope

Because v1 stops at Recommend, the active v1 audit trail should cover:

* Finding creation or recurrence.
* Recommendation creation.
* Recommendation updates.
* Alert-delivery events where retained.
* Resolution.
* Configuration or migration events only when already represented.

Do not build v3 approval/execution audit workflows into v1.

### Required rules

* Persist state transition and its audit entry in one transaction.
* Audit entry records:

  * Stable object ID.
  * Previous state.
  * New state.
  * Timestamp.
  * Actor category where meaningful.
  * Reason or source.
* No audit entry for a transition that failed.
* No transition without its required audit record.
* Simulation code must not append `Simulated` unless the corresponding state actually exists and is intentionally part of the enabled product.

### Tamper expectations

Do not claim cryptographic immutability unless implemented.

For v1 implement the smallest truthful guarantee:

* Application API exposes append-only writes.
* No normal storage method updates or deletes audit rows.
* Database-level triggers may deny normal `UPDATE` and `DELETE` operations on audit rows.
* Document that a local administrator with raw filesystem/database access can still alter the database unless cryptographic tamper evidence is implemented.

A hash chain is optional only if approved separately. Do not add one merely to satisfy marketing language.

### Required tests

* State and audit entry commit together.
* Failed transition commits neither.
* Simulation cannot create a false audit transition.
* Storage trait has no normal audit update/delete method.
* Database rejects audit mutation if append-only triggers are selected.
* Documentation uses accurate wording.

### Acceptance criteria

* Last audit state equals actual persisted object state.
* No false transition remains possible through normal application paths.
* Claims of immutability are corrected to match implementation.

---

# Phase 3 — Complete the trustworthy v1 vertical slice

---

## Work Package 3.1 — Implement meaningful self-observability

### Audit finding

* `RIEKO-AUDIT-008`

### Objective

Make status reflect whether Rieko is actually operating correctly.

### Minimum status model

Expose:

* Process version.
* Schema version.
* Process uptime.
* Deployment read-only capability derived from build/runtime capability, not hardcoded.
* Last ingestion attempt.
* Last successful ingestion.
* Last detector-cycle attempt.
* Last successful detector cycle.
* Source type.
* Source connectivity state.
* Source data timestamp when available.
* Source freshness or age.
* Last successful persistence cycle.
* Alert sink state when configured.
* LLM configuration state without exposing secrets.
* Database health.
* Overall state:

  * Healthy.
  * Degraded.
  * Unhealthy.
  * Not yet initialized.

Do not perform million-row queries to calculate status.

Persist small operational state records or aggregate counters suitable for constant-size status queries.

### Health semantics

Define exact rules.

Examples:

* HTTP server alive but no ingestion ever completed: not initialized.
* Latest ingestion failed but recent valid data exists: degraded.
* Data exceeds configured freshness threshold: degraded or unhealthy according to policy.
* Database integrity failure: unhealthy.
* LLM unavailable while deterministic detection works: degraded only when explanations are configured as expected; otherwise healthy.
* Telegram unavailable: degraded when configured.
* Read-only must reflect actual compiled capabilities.

Do not call a zero-data database healthy without qualification.

### Required tests

* Empty fresh DB.
* Successful fixture scan.
* Stale data.
* Last ingestion failed.
* Database failure.
* LLM absent by choice.
* Configured LLM failing.
* Telegram configured and failing.
* Status queries remain bounded.

### Acceptance criteria

* `/status` reflects actual operational freshness.
* CLI `status` uses the same semantics.
* No hardcoded `read_only: true`.
* Status never exposes secrets.

---

## Work Package 3.2 — Make recommendations conservative and evidence-backed

### Audit finding

* `RIEKO-AUDIT-010`

### Objective

Remove unsafe hardcoded operational parameters and provide recommendations that do not overstate certainty.

### Required recommendation structure

A recommendation should contain:

* Source finding ID.
* Action category.
* Human-readable recommendation.
* Evidence reference.
* Preconditions.
* Expected operational effect.
* Risks or trade-offs.
* Uncertainty or limitation.
* Whether the advice is informational or operator-actionable.
* No execution authority.

Do not require an LLM to populate these fields.

### Required correction

Remove unsupported hardcoded values such as:

* Universal `fee_rate_ppm: 1`.
* Universal `base_fee_msat: 0`.
* Universal `cltv_delta: 40`.
* Universal target ratio of `0.5`.
* Automatic “splice-in,” “splice-out” or rebalance advice where input evidence does not justify it.

For the current v1 liquidity detector, recommendations may be intentionally modest, for example:

* Review the channel’s intended role.
* Confirm whether the imbalance is expected.
* Inspect recent forwarding direction.
* Consider rebalancing only after validating cost and routing strategy.
* Monitor recurrence.

Only include numerical values if they are directly derived from configured operator policy or available evidence and the derivation is tested.

### Required tests

* Same finding produces same recommendation.
* No unsupported mutation parameter appears.
* Recommendation preserves finding provenance.
* Critical severity does not automatically generate executable advice.
* LLM disabled yields a complete structured recommendation.
* LLM text cannot alter action type or parameters.

### Acceptance criteria

* Recommendations are deterministic.
* No recommendation presents arbitrary fee changes.
* Advice states limitations.
* Recommendations stop at human decision support.

---

## Work Package 3.3 — Improve the minimum liquidity semantics required for v1

### Audit finding

* Critical v1 subset of `RIEKO-AUDIT-011`

### Objective

Correct clearly invalid liquidity calculations without expanding into a complete routing intelligence model.

### Required v1 corrections

Implement only semantics available from the current ingestion path or safely obtainable through the same read-only source:

* Validate that balances are not negative.
* Handle `local_balance > capacity` as invalid data rather than a liquidity class.
* Handle zero capacity explicitly.
* Distinguish unknown data from balanced data.
* Preserve active/inactive/closing state.
* Do not call every imbalance operationally harmful.
* Phrase the detector result as a liquidity condition or risk signal rather than proof of a problem.
* Use reserve-adjusted or spendable liquidity only if the required fields are reliably available and correctly normalized.

Do not implement full:

* Routing strategy inference.
* Automated channel role discovery.
* Fee optimization.
* HTLC-flow forecasting.
* Node-wide rebalancing optimization.

Those belong to later work.

### Detector semantics

Define documented v1 thresholds.

For every threshold include:

* Meaning.
* Unit.
* Boundary handling.
* Configuration status.
* Rationale as a heuristic, not universal truth.

Add a detector version when semantics change.

### Required tests

* Zero capacity.
* Balance greater than capacity.
* Missing balance.
* Inactive channel.
* Force-closing channel.
* Exact threshold boundaries.
* Intentionally imbalanced input.
* Stable evidence output.
* No recommendation of direct mutation.

### Acceptance criteria

* Invalid input cannot be classified as a normal healthy or drained channel.
* “Imbalanced” is not synonymous with “operator must rebalance.”
* Evidence clearly shows how the condition was calculated.

---

## Work Package 3.4 — Keep simulation isolated from v1 state

### Audit finding

* `RIEKO-AUDIT-022`

### Objective

Prevent any retained future simulation library from rerunning or mutating the v1 detection pipeline.

### Preferred v1 resolution

The default v1 product should not expose simulation.

If the crate remains for future development:

* Keep projection functions pure.
* Give them explicit inputs.
* Do not let them ingest.
* Do not let them detect.
* Do not let them persist findings.
* Do not let them append production audit transitions.
* Do not expose them in CLI/API/frontend.

Do not spend substantial time designing v2 simulation workflows during v1 hardening.

### Required tests

* Default CLI has no simulation command.
* Default API has no simulation route.
* Frontend has no simulation page.
* Pure projection library tests remain independent of SQLite and LND.

### Acceptance criteria

* Running v1 cannot create simulated state.
* Simulation cannot duplicate findings or recommendations.
* Future-facing code remains isolated.

---

## Phase 3 release gate

The project may be considered a credible `v0.1.0-alpha` candidate only when:

* Phases 1 and 2 pass.
* Status reflects real freshness and failures.
* Recommendations contain no arbitrary execution parameters.
* Liquidity detection handles invalid boundary data correctly.
* Simulation and execution are absent from the default product.
* Full fixture vertical-slice integration tests pass.
* The README accurately states current limitations.

---

# Phase 4 — Harden operator-facing interfaces

---

## Work Package 4.1 — Harden Telegram delivery

### Audit finding

* `RIEKO-AUDIT-013`

### Objective

Prevent Telegram failures from hanging the detection loop or breaking messages.

### Required implementation

Add:

* Finite connection and request timeout.
* Limited retry policy with backoff.
* No infinite retry.
* Correct escaping for the selected Telegram parse mode.
* Message truncation within Telegram limits.
* Clear delivery error.
* Redaction of secrets.
* Separation between finding persistence and alert delivery.

Do not introduce a durable queue service.

If delivery fails:

* Detection and persistence must still complete.
* Failure should be reflected in operational status.
* Cooldown must not be consumed as successful.
* A later cycle may retry according to bounded policy.

### Required tests

* Timeout.
* HTTP 500.
* Malformed response.
* Markdown metacharacters in untrusted fields.
* Oversized message.
* Secret redaction.
* Scan completes despite delivery failure.

### Acceptance criteria

* Telegram cannot block indefinitely.
* Untrusted text cannot break the message format.
* Alert failure does not invalidate findings.

---

## Work Package 4.2 — Harden API exposure

### Audit finding

* `RIEKO-AUDIT-014`

### Objective

Make local operation safe and prevent accidental unauthenticated network exposure.

### Default binding

Keep:

`127.0.0.1`

When a non-loopback address is supplied:

* Refuse by default.
* Require an explicit unsafe/external exposure acknowledgement.
* Require authentication before permitting external exposure.
* Display a clear warning.

Do not silently expose `0.0.0.0`.

### Authentication

Implement the smallest suitable v1 protection for non-loopback use:

* Static bearer token loaded from a protected file or environment variable.
* Constant-time comparison where appropriate.
* No user-account system.
* No session database.
* No OAuth.
* No role-based access system.

Loopback operation may remain unauthenticated if the threat model and browser controls are properly addressed.

### Browser and HTTP controls

Add:

* Same-origin CORS policy.
* Trusted-host validation where applicable.
* Content Security Policy.
* `X-Content-Type-Options`.
* Frame protection using CSP or appropriate header.
* Referrer policy.
* Safe cache policy for sensitive API data.
* Request-size limits.
* Route pagination.
* Bounded database queries.
* Appropriate timeouts.

Because simple cross-origin GET requests can still be sent by browsers, do not treat missing CORS permission as a complete localhost defence.

### Async database handling

Do not hold `std::sync::Mutex` around large blocking SQLite operations on the Tokio executor.

Use the smallest safe option, such as:

* `spawn_blocking` around bounded SQLite operations.
* A purpose-built storage access layer with controlled blocking tasks.

Do not add an async database framework solely for this.

### Status query correction

Replace million-row loads with bounded aggregate queries.

### Required tests

* Default loopback bind succeeds.
* External bind without acknowledgement fails.
* External bind without token fails.
* Authenticated external request succeeds.
* Unauthenticated external request fails.
* Security headers exist.
* Cross-origin behaviour follows policy.
* List endpoints enforce limits.
* Status uses bounded SQL.
* Large tables do not cause full-row materialization.

### Acceptance criteria

* Accidental external exposure is prevented.
* External access requires a token.
* API queries are bounded.
* Tokio runtime is not blocked by unbounded SQLite reads.

---

## Work Package 4.3 — Add bounded storage retention

### Audit finding

* `RIEKO-AUDIT-016`

### Objective

Prevent indefinite snapshot and in-memory event growth.

### Required design

Introduce a simple configurable retention policy.

Define:

* Default snapshot retention period.
* Optional maximum rows per channel if needed.
* Cleanup interval.
* Behaviour for closed channels.
* In-memory history bounds.
* Operator override.
* Effect on detector requirements.

Do not introduce a separate analytics database.

### Safety rules

* Never delete active findings solely because snapshots expire.
* Preserve enough history for the active v1 detector.
* Cleanup must be transactional.
* Cleanup activity must be observable.
* Retention configuration must be documented.

### Required tests

* Old snapshots are removed.
* Recent snapshots remain.
* Closed-channel stale history is handled.
* Cleanup does not remove active finding evidence required by the current schema.
* In-memory buffers remain bounded.
* Large cleanup does not block indefinitely.

### Acceptance criteria

* Storage growth has a documented upper-bound strategy.
* The normal monitor loop performs bounded cleanup.
* Status reports cleanup failures.

---

## Work Package 4.4 — Correct LND event normalization

### Audit findings

* `RIEKO-AUDIT-019`
* `RIEKO-AUDIT-021`

### Objective

Correct known timestamp, channel-ID and channel-status normalization defects.

### Required corrections

For forward/payment events:

* Use source timestamps.
* Do not replace event time with processing time.
* Define a stable unique event identity.
* Resolve LND channel IDs to the canonical channel identity used by domain objects.
* If reliable resolution is unavailable, preserve the raw ID explicitly and do not claim correlation.

For channel status:

* Verify bit semantics from the LND version/API model used by the client.
* Handle unknown or malformed flags as unknown/error.
* Do not default malformed data to active.
* Add explicit tests for known combinations.
* Preserve raw source value for evidence where useful.

Do not build event-based detectors in this work package.

### Acceptance criteria

* Source timestamps remain intact.
* IDs are not fabricated from collision-prone field concatenation.
* Unknown flags cannot silently become active.
* Normalizer tests document supported semantics.

---

# Phase 5 — Deliver a reproducible single-binary release and enforce CI

---

## Work Package 5.1 — Embed the frontend in the Rust binary

### Audit finding

* `RIEKO-AUDIT-009`

### Objective

Satisfy the literal one-binary deployment decision.

### Required outcome

The release binary must serve the frontend without requiring:

* Node.js at runtime.
* An external `frontend/dist` directory.
* A specific working directory.
* A manually copied static-assets folder.

### Implementation constraints

Use a small established embedding approach such as:

* Compile-time generated Rust asset module.
* `rust-embed`.
* An equivalent minimal crate.

Do not create a custom archive format.

The build must:

1. Install frontend dependencies in CI.
2. Run frontend validation.
3. Build static assets.
4. Embed those assets into the Rust binary.
5. Fail clearly when the asset build is missing.

Development mode may optionally serve filesystem assets, but the release build must embed them.

### Required tests

* Build release artifact.
* Copy only the binary into an empty directory.
* Start `serve`.
* Load `/`.
* Load frontend assets.
* Refresh a frontend route if client-side routing exists.
* Confirm no Node runtime is required.

### Acceptance criteria

* One copied binary serves API and frontend.
* Release packaging is reproducible.
* README no longer requires `--static-dir` for the normal release.

---

## Work Package 5.2 — Strengthen Rust and frontend CI

### Audit finding

* `RIEKO-AUDIT-017`

### Objective

Prevent regression of the exact defects found by the audit.

### Required Rust checks

CI should enforce:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
```

Add:

* Dependency advisory check.
* License policy using a committed configuration.
* Duplicate or banned dependency policy only where justified.
* Minimum supported Rust-version check.
* Current stable Rust check.
* Idempotent replay integration test.
* Migration tests.
* Read-only capability test.
* Alert restart test.
* Fixture vertical-slice test.
* Single-binary packaging test.

Do not add a CI job without a clear release gate.

### Frontend CI

Add only scripts needed by the current Svelte project:

* Type checking with `svelte-check`.
* Linting if a linter is configured.
* Focused unit tests for API client and critical rendering behaviour.
* Production build.

Do not install a broad frontend testing stack without specific tests.

### Workflow security

* Set minimum required workflow permissions.
* Pin third-party actions to commit SHAs where practical.
* Avoid exposing secrets to pull-request workflows.
* Separate release permissions from normal CI.
* Retain artifacts only as needed.

### Repository files

Add proportionate project governance:

* `SECURITY.md`
* Dependency update configuration
* Release instructions
* Supported-version statement

Do not add a complex contributor bureaucracy for an early project.

### Acceptance criteria

* Every v1 release gate has a corresponding automated check or documented manual check.
* CI fails when execution is accidentally enabled.
* CI fails on replay duplication.
* CI fails on migration breakage.
* CI produces or verifies the self-contained artifact.

---

## Work Package 5.3 — Create a release workflow

### Objective

Produce a traceable `v0.1.0-alpha` artifact.

### Required output

At minimum:

* Release binary for the initially supported platform.
* Embedded frontend.
* Version information.
* Commit identifier where feasible.
* SHA-256 checksum.
* Release notes.
* License.
* Basic SBOM if supported by the existing toolchain without excessive complexity.

Do not claim multi-platform support without CI evidence.

### Release verification

On a clean environment:

* Run the binary.
* Create/open database.
* Run fixture scan.
* Serve frontend.
* Query status.
* Confirm simulation/execution are unavailable.
* Confirm no external assets are needed.

### Acceptance criteria

* Artifact can be independently verified.
* Supported platform is explicit.
* Release does not enable post-v1 features.

---

# Phase 6 — Validate controlled LND integration

This phase begins only after Phases 1–5 pass.

Do not begin with mainnet.

---

## Work Package 6.1 — Create an opt-in LND regtest integration harness

### Audit gap

* Regtest/live-node integration coverage was absent.

### Objective

Validate the real LND REST schema, TLS and read-only macaroon behaviour without risking funds.

### Scope

The harness should verify only endpoints used by Rieko v1.

It should test:

* TLS certificate trust.
* Restricted macaroon authentication.
* Channel-list ingestion.
* Normalization.
* Node/network identity.
* Source freshness.
* Retry and timeout behaviour.
* Read-only access.
* Failure on insufficient permissions.
* Failure on wrong TLS certificate.
* Failure on wrong node/network assumptions.

Do not test mutation.

### Constraints

* Keep it opt-in if the environment is expensive.
* Document prerequisites.
* Keep deterministic fixture tests as the normal fast CI path.
* Do not require Docker if the repository does not already depend on it; choose the simplest repeatable harness available.
* Do not connect to public mainnet infrastructure.

### Acceptance criteria

* Rieko successfully reads a controlled LND regtest node.
* Restricted macaroon is sufficient.
* No admin macaroon is required.
* No mutation request is sent.
* Tests demonstrate reconnect and error handling.

---

## Work Package 6.2 — Add controlled local observation validation

### Objective

Define a manual release-candidate procedure before any mainnet observation.

### Procedure must verify

* Operator-generated restricted read-only macaroon.
* Explicit TLS certificate path.
* Loopback-only API.
* Fresh empty or backed-up database.
* Status reports connected/fresh.
* No LLM configured for the first test.
* No Telegram configured for the first test.
* One observation cycle.
* Verify findings against the operator’s LND UI/CLI.
* Stop the process.
* Restart.
* Verify no duplicate records.
* Enable Telegram only after core observation is verified.
* Enable an LLM only after confirming data-sharing implications.

### Mainnet restriction

Mainnet observation remains conditional until:

* All P0, P1 and P2 audit blockers are resolved.
* Regtest integration passes.
* Read-only feature check passes.
* Operator documentation is complete.
* Release artifact is reproducible.

Rieko must remain local and read-only.

---

# Phase 7 — Explicit post-v1 backlog

Do not implement this phase during v1 remediation.

Track these items separately.

## 7.1 Full liquidity semantics

Related audit finding:

* Remaining scope of `RIEKO-AUDIT-011`

Potential later work:

* Channel reserves.
* Pending HTLCs.
* Commitment-fee effects.
* Spendable liquidity.
* Actual fee policy.
* Operator-defined channel roles.
* Routing-strategy context.
* Node-wide liquidity objectives.

This requires a separate design decision and real-world evaluation data.

## 7.2 Graph purpose decision

Related audit finding:

* `RIEKO-AUDIT-020`

Choose later between:

* Keeping the graph as a minimal protocol-neutral state store.
* Adding graph operations required by actual detectors.
* Renaming it if it remains a keyed state collection.

Do not add graph algorithms merely to justify the crate’s name.

## 7.3 Detector number two

The drift detector must remain experimental until:

* The first liquidity slice satisfies all v1 gates.
* Historical persistence is trustworthy.
* Retention semantics are fixed.
* Stable finding identity exists.
* False-positive evaluation exists.

## 7.4 Simulation and execution

Simulation is v2.

Approval and execution are v3.

They require separate ADRs covering:

* Threat model.
* Authentication.
* Authorization.
* Human approval.
* Exact action preview.
* Simulation accuracy.
* Rollback limitations.
* Node permissions.
* Audit guarantees.
* Failure recovery.
* Separate release features.

Do not reactivate existing execution code merely because Phase 1 isolated it.

---

# 4. Cross-phase test strategy

Maintain a small, purposeful test pyramid.

## Unit tests

Use for:

* Domain validation.
* Deterministic IDs.
* Detector thresholds.
* Recommendation mapping.
* Status calculation.
* Alert cooldown rules.
* Normalizer field mapping.
* State transitions.

## Integration tests

Use real SQLite for:

* Replay idempotency.
* Transactions.
* Migrations.
* Audit/state atomicity.
* Alert persistence.
* Concurrent read/write.
* Retention.
* Status persistence.

## CLI integration tests

Verify:

* Commands exposed in default v1.
* Execution and simulation unavailable.
* Fixture scan.
* Status.
* Serve defaults.
* Non-loopback guard.
* Exit codes.
* Secret-safe errors.

## HTTP integration tests

Verify:

* Status semantics.
* Pagination.
* Authentication.
* Security headers.
* Loopback/external policy.
* Embedded static assets.
* Bounded query behaviour.

## Regtest tests

Use only for:

* LND TLS.
* Macaroon permissions.
* Real REST payload compatibility.
* Reconnection.
* Network identity.
* Read-only ingestion.

## Tests not required for v1

Do not add:

* Large distributed load systems.
* Kubernetes tests.
* Multi-region tests.
* PostgreSQL tests.
* Machine-learning evaluation.
* Autonomous execution tests.
* Complex browser end-to-end suites unless a critical user workflow requires one.

---

# 5. Required documentation updates

Update documentation alongside the relevant phase.

## README

Must accurately cover:

* What Rieko v1 does.
* What it explicitly does not do.
* Read-only guarantee.
* Supported LND path.
* Restricted macaroon requirement.
* TLS certificate requirement.
* Fixture quick start.
* Database location.
* Backup before upgrade.
* Status interpretation.
* Telegram behaviour.
* LLM privacy implications.
* API binding defaults.
* External-bind authentication.
* Single-binary usage.
* Supported platform.
* Known limitations.

Remove or correct:

* `admin.macaroon` recommendations.
* Reachable execution examples.
* Simulation as a v1 capability.
* Claims of immutable audit history unless technically accurate.
* Claims that Bitcoin Core ingestion is complete.
* External `frontend/dist` instructions after embedding.
* Any claim that imbalance automatically requires rebalancing.

## ADR clarification

Create a focused ADR amendment or follow-up ADR clarifying:

1. “One binary” means embedded frontend assets in the release artifact.
2. Future simulation/execution crates may exist only as unreachable interfaces in v1.
3. V1 read-only means no mutation-capable path exists in the default build.
4. The exact minimum LND permission set.
5. Audit guarantees are append-only through normal application paths, with local-admin limitations stated.
6. LLM data boundaries.
7. Status freshness semantics.
8. Detector versioning.
9. Initially supported Bitcoin/Lightning networks.

Do not rewrite ADR-0001 wholesale.

---

# 6. Agent execution protocol

For every work package, return this structure.

## A. Finding confirmation

* Audit finding IDs.
* Current status.
* Exact evidence.
* Whether repository state changed since the audit.

## B. Proposed minimal change

* Files affected.
* Behaviour changed.
* Behaviour deliberately left unchanged.
* Why the change is the smallest sufficient correction.

## C. Tests first

* Test that reproduces the defect.
* Expected failure before implementation.
* Expected pass afterward.

## D. Implementation

* Summary of code changes.
* Schema changes.
* API or CLI changes.
* Documentation changes.

## E. Validation

Include exact results for:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Also run the work-package-specific integration tests.

## F. Acceptance-criteria matrix

For every criterion mark:

* PASS
* FAIL
* NOT VERIFIED
* NOT APPLICABLE

Do not use “mostly complete.”

## G. Remaining risks

List only risks that remain after the change.

## H. Stop point

Stop after the work package and wait for review unless explicitly authorized to continue.

---

# 7. Phase completion reports

At the end of each phase, produce:

## Phase verdict

* Complete.
* Incomplete.
* Blocked.

## Audit findings resolved

List finding IDs and evidence.

## Audit findings remaining

List finding IDs and why.

## Architecture status

State whether ADR decisions D1–D9 are:

* Compliant.
* Partial.
* Violated.
* Unverified.

Only update rows affected by the phase.

## Regression result

Report:

* Workspace build.
* Tests.
* Clippy.
* Formatting.
* Replay test.
* Migration test where applicable.
* Read-only test.
* Fixture vertical slice.
* Frontend check.
* Artifact check where applicable.

## Release eligibility

Mark:

* Fixture-only development.
* Regtest.
* Local read-only mainnet observation.
* Remote API exposure.
* Unattended operation.
* `v0.1.0-alpha`.

Use:

* PASS
* CONDITIONAL
* FAIL
* NOT VERIFIED

---

# 8. Final v1 release gates

Rieko `v0.1.0-alpha` may be released only when every required gate passes.

## Architecture

* Default release contains no reachable LND/Core mutation.
* Simulation and execution are absent from CLI/API/frontend.
* Detectors remain independent of the LLM.
* Production uses one Rust runtime and SQLite.
* Frontend is embedded in the release binary.

## Correctness

* Identical replay creates zero duplicate findings.
* Identical replay creates zero duplicate recommendations.
* Identical replay creates zero false audit entries.
* Findings have stable deterministic identity.
* Findings include detector version.
* Invalid persisted evidence fails loudly.
* Detector boundary cases pass.

## LND safety

* Macaroon bytes are hex encoded.
* TLS certificate is explicitly trusted.
* Default documentation uses a restricted macaroon.
* Regtest read-only ingestion passes.
* No mutation request is possible in the v1 build.

## Storage

* Schema is versioned.
* Migration tests pass.
* Cycle persistence is transactional.
* Busy timeout is configured.
* Integrity failure is reported.
* Alert cooldown survives restart.
* Retention is configured and tested.

## Recommendations

* No arbitrary fee-policy parameters.
* No recommendation implies guaranteed outcomes.
* Preconditions, effect, risk and limitations are represented.
* LLM cannot alter the structured recommendation.

## Observability

* Status exposes last ingestion and detector cycle.
* Status exposes freshness.
* Status exposes source state.
* Status exposes database health.
* Status reports degraded conditions.
* Status does not hardcode read-only capability.

## API

* Loopback is the default.
* Non-loopback requires explicit acknowledgement and authentication.
* Security headers are present.
* Queries are bounded.
* Blocking SQLite work is moved off the async executor.
* No secrets appear in responses.

## Delivery

* CI runs all required Rust checks.
* CI runs replay and migration tests.
* CI checks the read-only build.
* Frontend validation passes.
* Release artifact contains embedded assets.
* The binary runs from an empty directory.
* Checksum and supported platform are published.
* Operator documentation matches actual behaviour.

---

# 9. Final product boundary

The completed Rieko v1 alpha is:

* A local, self-hosted operational intelligence engine.
* One Rust binary.
* One SQLite database.
* Read-only toward LND and Bitcoin Core.
* Rules-first.
* LLM-optional.
* Evidence-backed.
* Restart-safe for operational state.
* Explicit about uncertainty.
* Designed to inform a human operator.

It is not:

* An autonomous node manager.
* A fee-setting bot.
* A rebalancing engine.
* A channel execution controller.
* A general AI agent.
* A multi-node cloud platform.
* A compliance product.
* A machine-learning anomaly service.

Preserve the core principle:

**Evidence first, explanation second, human authority always.**
