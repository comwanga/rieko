# Rieko High-Level Architecture, Security and Production-Readiness Audit

Conduct a rigorous, repository-backed audit of the entire Rieko project:

Repository: `https://github.com/comwanga/rieko.git`

Rieko is an operational intelligence engine for Bitcoin and Lightning infrastructure. It is not an AI application. Its purpose is to observe a node operator’s environment, detect and correlate operational anomalies, produce typed findings backed by structured evidence, explain those findings in plain language, and recommend safe operator actions.

The authoritative architecture is:

`docs/adrs/0001-rieko-v1-architecture.md`

Treat ADR-0001 as the accepted architecture contract. Audit the implementation against it, but do not assume the ADR is automatically correct. Identify:

1. Where the implementation violates the ADR.
2. Where the ADR creates security, reliability or maintainability risks.
3. Where the implementation technically complies but misses the architectural intent.
4. Where implemented features have moved beyond the approved v1 scope.
5. Which missing controls could make Rieko unsafe or misleading for real Bitcoin/Lightning node operators.

## Operating mode

This is an audit and planning task, not an implementation task.

Do not modify code during the initial audit.

Do not create commits, branches, pull requests or issues.

Do not generate speculative findings based only on filenames or README claims.

Inspect the actual implementation, tests, configurations, workflows, migrations, fixtures and dependency graph.

Every material finding must include exact repository evidence such as:

* File path.
* Relevant module, type, function or configuration.
* Line number or narrow line range where practical.
* Explanation of the actual execution path.
* Why the behaviour matters operationally.

Clearly distinguish among:

* Verified implementation.
* Partial implementation.
* Documentation-only claim.
* Missing implementation.
* Dead, unreachable or placeholder code.
* Inference requiring runtime validation.

Do not praise scaffolding as a completed capability.

## Foundational architecture contract

Audit the repository against the following frozen decisions.

### A. Intelligence engine, not an AI product

Detection and correlation must be deterministic or rules-based in v1.

LLMs may translate already-structured evidence into human-readable explanations, but must never:

* Decide whether an anomaly exists.
* Invent evidence.
* Change finding severity.
* Select or authorize executable actions.
* Bypass deterministic recommendation logic.
* Become necessary for the detector pipeline to complete.

The engine must remain useful when the LLM is unavailable, slow, misconfigured or returns malformed output.

### B. Language-per-layer with one production runtime

The intended boundaries are:

* Rust: production engine, graph, detectors, storage, recommendations, alerts, LLM client, API and CLI.
* Python: offline experimentation, backtesting and ONNX export only.
* TypeScript: Svelte frontend only, compiled into static assets served by the Rust binary.

Production must not require a Python server, Node server, Redis, Kafka, Kubernetes, a message broker or independently deployed microservices.

### C. Frozen deployment shape

The v1 operational shape is:

* One Rust binary.
* One production runtime.
* SQLite with WAL.
* Axum API serving both API routes and static frontend assets.
* Self-hosted on operator hardware.
* Read-only behaviour by default.
* No unattended mutation of node state.

Verify whether the distributed artifact is genuinely self-contained or whether users must manually install, build or operate additional runtime components.

### D. Domain layer as the kernel

The intended pipeline is:

`LND / Bitcoin Core → Normalizers → Domain Objects → Graph → Detectors`

Protocol response objects must not flow directly into general detectors.

The domain model should contain operational meaning, not merely rename fields from LND or Bitcoin Core.

Check whether concepts such as channel health, liquidity profile, risk state, node state and evidence provenance are genuinely modelled or computed elsewhere through protocol-specific assumptions.

A raw-event escape hatch may exist, but it must be explicit, narrow and justified.

### E. Enforced dependency direction

The intended crates are:

* `rieko-domain`
* `rieko-graph`
* `rieko-storage`
* `rieko-ingest-core`
* `rieko-ingest-lnd`
* `rieko-detectors`
* `rieko-findings`
* `rieko-recommendations`
* `rieko-alerts`
* `rieko-llm`
* `rieko-api`
* `rieko-cli`

The kernel rule is especially important:

* `rieko-domain` must remain independent of infrastructure concerns.
* `rieko-graph` should depend only on `rieko-domain` and carefully justified third-party primitives.
* Ingesters must not own detector policy.
* Detectors must not depend on API, CLI, LLM, Telegram or concrete storage infrastructure.
* Recommendations must consume typed findings rather than rediscover anomalies independently.
* API and CLI should act as composition layers rather than containers for business logic.

The repository currently also contains workspace members named `rieko-simulation` and `rieko-execution`. Determine whether these are:

* Legitimate future-facing interfaces with no v1 execution path.
* Premature scope expansion.
* Architectural placeholders.
* Reachable production capabilities.
* A violation of the v1 Observe → Explain → Recommend boundary.

### F. SQLite-first storage

Verify that SQLite is correctly configured and operated, including:

* WAL activation and verification.
* Busy timeout.
* Foreign-key enforcement.
* Transaction boundaries.
* Schema migrations.
* Upgrade and rollback behaviour.
* Crash recovery.
* Concurrent monitor/API access.
* Connection ownership.
* Database locking behaviour.
* Corruption handling.
* Retention or compaction strategy.
* Idempotent persistence.
* Uniqueness constraints.
* Indexes for real query paths.
* Safe handling of timestamps.
* Safe handling of large historical datasets.

Verify that the storage abstraction is meaningful rather than a leaky wrapper around SQLite-specific assumptions.

### G. Action progression and auditability

The long-term model is:

`Observe → Explain → Recommend → Simulate → Approve → Execute`

V1 must stop at Recommend.

Audit whether:

* Every recommendation maps to a typed action.
* Action state transitions are explicit and validated.
* Unsupported transitions are impossible or rejected.
* Findings, recommendations, simulations and future executions have stable identifiers.
* Every action or recommendation is appended to a tamper-evident-enough operational audit trail.
* Audit entries record time, source, evidence, actor and state transition.
* Historical entries can be silently overwritten or deleted.
* Simulation or execution code is reachable through the CLI, API or internal orchestration.
* Any path can mutate LND, Bitcoin Core, local configuration or system state.
* Human approval is structurally required before any future execution path.

Do not assume that a type named `Simulation` or `Execution` is safe. Trace call paths.

### H. One vertical slice before detector expansion

The intended first production slice is:

`Ingest → Normalize → Store → Detect → Finding → Explain → Alert → Persist`

The approved first detector is channel liquidity or imbalance.

Determine whether this entire path is complete, internally consistent and testable against both fixtures and realistic node data.

Identify whether extra detectors were added before the first slice became production-ready.

## Audit workstreams

Use multiple specialized OpenCode agents where useful, but consolidate their work into one coherent report. Avoid duplicated findings.

### 1. Repository and build-system audit

Inspect:

* Workspace structure.
* Crate manifests.
* Feature flags.
* Binary targets.
* Build scripts.
* Frontend build integration.
* Static asset embedding or runtime loading.
* Release profiles.
* Minimum supported Rust version.
* Dependency versions.
* Lockfile policy.
* Platform assumptions.
* Licensing metadata.
* Reproducibility.
* Cross-compilation.
* Release artifact creation.
* Installation and upgrade process.

Run, where supported:

```bash
cargo metadata --no-deps --format-version 1
cargo tree --workspace
cargo tree --workspace --duplicates
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo doc --workspace --no-deps
```

For the frontend, inspect its actual package manager and scripts before running commands. Then run the appropriate equivalents of:

```bash
npm ci
npm run check
npm run lint
npm run test
npm run build
```

Do not silently substitute passing commands for missing quality gates. Report absent scripts.

### 2. Dependency-boundary audit

Build the real crate dependency graph.

Identify:

* Cyclic dependencies.
* Reverse dependencies into the kernel.
* Protocol SDK leakage into domain types.
* Infrastructure types exposed through public interfaces.
* Business logic in API or CLI crates.
* Storage-specific types crossing abstraction boundaries.
* Detector dependence on LND-specific data.
* Recommendation logic duplicated across layers.
* Unnecessary public APIs.
* Feature flags that alter architectural guarantees.
* Dead crates or crates included only to satisfy the planned architecture diagram.

Classify each boundary as:

* Enforced.
* Convention-only.
* Violated.
* Unverifiable.

Recommend automated architectural checks where appropriate.

### 3. Domain-model audit

Assess whether the domain model captures real operational semantics for Bitcoin and Lightning infrastructure.

Review:

* Identity and canonical IDs for nodes, channels, peers and observations.
* Channel directionality.
* Local versus remote balances.
* Capacity and reserve handling.
* Pending HTLCs.
* Offline or inactive channels.
* Private channels.
* Zero-capacity and malformed states.
* Closed or force-closing channels.
* Fee policy.
* Routing direction.
* Block height and time context.
* Chain and network identity.
* Unit safety between satoshis, millisatoshis, percentages and basis points.
* Timestamp semantics.
* Data freshness.
* Source provenance.
* Confidence and evidence quality.
* Optional and unknown values.
* Integer overflow and precision loss.
* Cross-source entity correlation.

Determine whether operational fields are first-class domain concepts or are derived inconsistently inside detectors and presentation layers.

### 4. LND ingestion audit

Trace the live-node ingestion path end to end.

Review:

* REST or gRPC transport.
* TLS certificate verification.
* Hostname validation.
* Macaroon loading and handling.
* Macaroon permission scope.
* Whether documentation recommends an unnecessarily powerful `admin.macaroon`.
* Secret exposure through command-line arguments, process listings, logs, errors or telemetry.
* URL parsing.
* Timeout configuration.
* Retry strategy.
* Backoff and jitter.
* Pagination.
* Streaming or polling semantics.
* Reconnection.
* Partial responses.
* Duplicate data.
* Authentication errors.
* Rate limiting.
* Network mismatch.
* Node identity verification.
* Failure isolation.
* Fixture parity with real LND payloads.

Determine the minimum LND permissions actually required.

Recommend a least-privilege macaroon approach instead of accepting admin access by default.

### 5. Bitcoin Core ingestion audit

Trace all Bitcoin Core connectivity and normalization paths.

Review:

* RPC authentication.
* Cookie and credential handling.
* TLS or local-network assumptions.
* RPC timeout and retries.
* Network and chain verification.
* Node sync state.
* Initial block download.
* Pruned-node behaviour.
* Reorg handling.
* Stale block height.
* ZMQ assumptions, if any.
* Error mapping.
* Data freshness.
* Whether Core data is actually used by the v1 detector.
* Whether protocol-specific Core types leak past normalization.

Identify any claims of Core support that are only scaffolding.

### 6. Idempotency, replay and temporal correctness

This is a critical workstream.

Verify whether ingesters and storage remain correct under:

* Process restart.
* Node restart.
* Replayed fixture.
* Repeated polling of unchanged state.
* Duplicate source events.
* Out-of-order observations.
* Clock skew.
* Backfilled history.
* Reorgs.
* Channel state changes between requests.
* Partial ingestion failure.
* Database transaction failure.
* Alert delivery failure.
* LLM failure after finding persistence.
* Crash halfway through a scan cycle.

Inspect the per-source “last seen” or checkpoint ledger.

Determine whether it prevents double-counting without suppressing legitimate updates.

Verify that graph upserts and historical snapshots have explicit idempotency keys or uniqueness constraints.

### 7. Graph audit

Assess whether the graph is necessary, correct and reusable.

Review:

* Node and edge identity.
* Directed versus undirected semantics.
* Channel direction.
* Parallel channels.
* Graph update behaviour.
* Deleted or closed entities.
* Stale node cleanup.
* Snapshot consistency.
* Referential integrity.
* Memory growth.
* Concurrency.
* Serialization.
* Query complexity.
* Deterministic traversal.
* Whether detectors use the graph or bypass it.
* Whether the graph contains protocol-neutral domain objects.
* Whether graph state can diverge from persisted state.

Identify “graph theatre”: a graph abstraction that exists architecturally but adds no real analytical value.

### 8. Detector audit

For every detector found in the repository:

* State its purpose.
* Identify its input types.
* Trace the full algorithm.
* List thresholds and defaults.
* Identify configuration paths.
* Determine whether the detector is deterministic.
* Explain its evidence model.
* Check its severity calculation.
* Review false-positive and false-negative risks.
* Examine unit and boundary handling.
* Identify stale-data behaviour.
* Determine whether findings are stable across repeated runs.
* Check whether detector output is independent of LLM availability.
* Identify whether thresholds are justified or arbitrary.
* Verify whether the detector distinguishes an observation from a confirmed operational problem.

For the channel liquidity detector specifically, test cases should include:

* Balanced channel.
* Severe outbound depletion.
* Severe inbound depletion.
* Near-threshold values.
* Zero capacity.
* Local balance greater than capacity.
* Missing balance data.
* Inactive channel.
* Offline peer.
* Private channel.
* Pending HTLCs.
* Reserve-adjusted spendable balance.
* Rapid drift across snapshots.
* Duplicate snapshots.
* Old snapshots.
* Single-channel node.
* Large node with many channels.

Check whether “imbalance” alone is treated as automatically harmful without considering node role, routing strategy or channel intent.

### 9. Findings and evidence audit

Review the typed findings model for:

* Stable finding ID.
* Detector ID and version.
* Finding schema version.
* Source and entity identity.
* Timestamp.
* Observation window.
* Severity.
* Confidence.
* Evidence.
* Human-readable summary.
* Machine-readable remediation metadata.
* Lifecycle state.
* Deduplication identity.
* Resolution and recurrence semantics.
* Compatibility across upgrades.

Verify that evidence is sufficient for an operator to independently understand why the finding exists.

Ensure LLM prose is not stored as if it were source evidence.

### 10. Recommendation audit

Trace finding-to-recommendation mappings.

Check whether recommendations:

* Are deterministic.
* Are typed.
* Preserve finding provenance.
* Express preconditions.
* State expected effect.
* State risk and trade-offs.
* Avoid claiming guaranteed outcomes.
* Distinguish informational advice from an actionable operation.
* Avoid recommending unsafe rebalancing or channel changes from incomplete data.
* Can be deduplicated.
* Can be audited.
* Can later be simulated without redesigning the model.
* Do not contain executable shell commands assembled from untrusted input.
* Cannot silently transition into execution.

Evaluate whether recommendations are operationally useful or only generic text.

### 11. LLM boundary and failure-mode audit

Inspect the actual LLM client and its callers.

Review:

* Endpoint configuration.
* API-key handling.
* OpenAI-compatible assumptions.
* Ollama compatibility claims.
* Timeouts.
* Retries.
* Rate limits.
* Context-size limits.
* Structured output validation.
* Prompt injection risks.
* Untrusted node metadata.
* Sensitive information sent to remote providers.
* Redaction.
* Data minimization.
* Logging.
* Error handling.
* Fallback explanation.
* Offline operation.
* Model configuration.
* Cost control.
* Determinism.
* Testability.
* Hallucination containment.

Verify that the LLM receives a bounded structured evidence envelope rather than raw logs, arbitrary RPC data or secrets.

The LLM output must be clearly labelled as explanation, not authoritative detection evidence.

Identify whether the engine remains fully functional without `RIEKO_LLM_*` variables.

### 12. Alerting audit

Inspect Telegram and any other alert channels.

Verify:

* Severity tiers.
* Deduplication key construction.
* Cooldown storage.
* Persistence across process restarts.
* Recovery after failed delivery.
* Retry and backoff.
* Rate limiting.
* Message-size handling.
* Telegram escaping and formatting.
* Untrusted content injection.
* Secret handling.
* Delivery status.
* Alert acknowledgement.
* Alert lifecycle.
* Resolution notification.
* Prevention of alert storms.
* Behaviour when the database is unavailable.
* Behaviour when Telegram is unavailable.

Test whether the same recurring condition is:

* Suppressed appropriately during cooldown.
* Re-alerted after cooldown.
* Escalated when severity increases.
* Resolved and allowed to alert again later.

Do not count in-memory suppression as production-grade deduplication unless loss on restart is explicitly accepted.

### 13. API and web-security audit

Audit every Axum route and middleware layer.

Review:

* Bind address defaults.
* Exposure beyond localhost.
* Authentication.
* Authorization.
* CORS.
* CSRF assumptions.
* Trusted-host enforcement.
* Request-body limits.
* Query limits.
* Pagination.
* Timeouts.
* Concurrency limits.
* Error disclosure.
* Secret leakage.
* Path traversal.
* Static file handling.
* MIME types.
* Cache headers.
* Content Security Policy.
* Clickjacking protection.
* Referrer policy.
* API versioning.
* Schema stability.
* JSON size.
* Database query amplification.
* Denial-of-service risk.
* Unsafe debug routes.
* Mutation routes.
* WebSocket or streaming routes, if present.

The v1 API should be read-only. Identify every route that can directly or indirectly mutate:

* Node state.
* Channel state.
* Bitcoin Core state.
* Rieko configuration.
* Findings.
* Recommendations.
* Simulations.
* Execution records.
* Audit history.
* Filesystem state.

Distinguish expected ingestion persistence from operator-triggered control-plane mutation.

### 14. CLI security and usability audit

Audit all CLI commands, flags and defaults.

Review:

* Secret-bearing CLI arguments.
* Environment-variable support.
* Config-file permissions.
* Destructive commands.
* Confirmation gates.
* Network defaults.
* Database defaults.
* Exit codes.
* Structured output.
* Signal handling.
* Graceful shutdown.
* Lock handling.
* Concurrent command execution.
* Logging defaults.
* Error messages.
* Redaction.
* Help accuracy.
* Feature discoverability.
* Safe handling of fixture paths and static asset paths.

Pay close attention to:

* `scan`
* `monitor`
* `serve`
* `status`
* Any simulation or execution commands

Verify that the README commands match the actual CLI.

### 15. Single-binary and frontend audit

Determine whether “one binary” is genuinely delivered.

Check whether:

* The frontend must be built separately.
* `frontend/dist` must exist beside the binary.
* Assets are embedded at compile time or loaded at runtime.
* The binary fails cleanly when assets are absent.
* The release process builds both layers.
* Node.js is required only at build time.
* The final artifact can be copied to a clean operator machine and run.
* The same binary supports scan, monitor, status and serve safely.
* Runtime working-directory assumptions exist.
* Static asset paths are safe and portable.

If the binary requires an external `frontend/dist` directory, classify the current state accurately instead of calling it a complete single-binary deployment.

### 16. Self-observability audit

Verify structured logs and the status endpoint.

Review whether Rieko exposes:

* Process health.
* Database connectivity.
* Last successful ingestion.
* Last attempted ingestion.
* Last detector cycle.
* Source freshness.
* LND/Core connectivity.
* Current network.
* Alert-delivery health.
* LLM health without exposing secrets.
* Queue or pending-work status.
* Build version and commit.
* Schema version.
* Degraded-mode indicators.
* Error counters.
* Uptime.

The status endpoint must not report healthy merely because the HTTP server is running.

Check logging for:

* Structured fields.
* Correlation IDs.
* Finding IDs.
* Scan-cycle IDs.
* Secret redaction.
* Log-level configuration.
* Log flooding.
* Actionable error context.

### 17. Concurrency and lifecycle audit

Inspect the Tokio task model and shared state.

Review:

* Task ownership.
* Cancellation.
* Shutdown.
* Panics in spawned tasks.
* Unbounded channels.
* Locks held across `.await`.
* Blocking SQLite work on async executors.
* Duplicate monitor loops.
* Overlapping scan cycles.
* Backpressure.
* Memory growth.
* Retry storms.
* Connection reuse.
* Resource cleanup.
* Partial startup.
* Partial shutdown.
* Signal handling.

Determine what happens when one subsystem fails while others remain alive.

### 18. Supply-chain and dependency-security audit

Run, where available:

```bash
cargo audit
cargo deny check
```

Also inspect:

* Unmaintained dependencies.
* Duplicate dependency versions.
* Git dependencies.
* Wildcard versions.
* Default features.
* Native dependencies.
* TLS backend.
* Unsafe code.
* Build scripts.
* Proc macros.
* Frontend dependency vulnerabilities.
* Secret scanning.
* Dependency update automation.
* SBOM generation.
* Release provenance.
* Artifact signing.
* License compatibility.

Do not treat a clean vulnerability scan as proof of application security.

### 19. CI/CD and repository-governance audit

Inspect `.github` and all automation.

Verify whether CI enforces:

* Formatting.
* Clippy.
* Tests.
* All targets.
* Relevant feature combinations.
* Frontend checks.
* Frontend build.
* Dependency audit.
* License checks.
* Architecture-boundary checks.
* Migration tests.
* Fixture tests.
* Real-node or regtest integration tests.
* Release build.
* Single-binary packaging.
* Documentation checks.
* Minimum supported Rust version.
* Current stable Rust.
* Multiple operating systems where relevant.

Review:

* Branch protection assumptions.
* Pinned action SHAs.
* Workflow permissions.
* Secret exposure.
* Pull-request permissions.
* Cache poisoning.
* Artifact retention.
* Release permissions.
* Dependabot or Renovate.
* CODEOWNERS.
* Security policy.
* Contribution guidance.
* Issue templates.
* Release process.

Report missing governance proportionately for the project’s current maturity.

### 20. Test-strategy audit

Map existing tests by crate and capability.

Classify them as:

* Unit.
* Integration.
* Contract.
* Fixture.
* Property-based.
* Fuzz.
* Migration.
* Security regression.
* End-to-end.
* Live-node/regtest.
* Frontend.
* Snapshot/golden.

Identify critical paths that have no effective tests.

Pay particular attention to:

* Normalizer correctness.
* Idempotent replay.
* Finding stability.
* Dedup persistence.
* Database migration.
* LLM failure.
* Telegram failure.
* Read-only guarantees.
* Simulation/execution isolation.
* API limits.
* Concurrent monitor and API access.
* Corrupt or adversarial fixture data.
* Very large channel sets.
* Regtest integration.

Recommend the smallest useful test pyramid for v1.

### 21. Documentation and operator-trust audit

Verify all README and ADR claims against code.

Review:

* Setup instructions.
* Prerequisites.
* LND permissions.
* Core permissions.
* Network support.
* Privacy impact.
* Data sent to LLM providers.
* Local-only mode.
* Database location.
* Backup and upgrade guidance.
* Security assumptions.
* Threat model.
* Failure behaviour.
* Alert guarantees.
* Detector limitations.
* Recommendation limitations.
* Supported platforms.
* Single-binary claim.
* Read-only claim.
* Recovery process.

Identify claims likely to create false operator confidence.

### 22. Scope-control audit

Detect premature implementation of post-v1 features, including:

* Multiple detectors before the liquidity slice is trustworthy.
* Simulation.
* Execution.
* Approval workflows.
* Cloud or multi-node architecture.
* PostgreSQL.
* DuckDB.
* Kafka or other brokers.
* Kubernetes.
* Security-intelligence feeds.
* CVE correlation.
* Proof-of-reserves.
* Compliance reporting.
* Autonomous remediation.
* ML-driven production detection.

For each out-of-scope component, recommend one of:

* Remove now.
* Keep as an isolated interface.
* Feature-gate and exclude from v1.
* Document as experimental.
* Retain because it is required to preserve the action-model contract.

## Threat model

Create a concise v1 threat model covering at least:

### Assets

* LND macaroon.
* Bitcoin Core credentials.
* TLS certificates.
* LLM API key.
* Telegram bot token.
* Node topology and channel data.
* Operational history.
* Findings and recommendations.
* Audit records.
* Local database.
* Operator trust.

### Adversaries and failures

* Remote attacker reaching the API.
* Malicious webpage reaching a localhost service.
* Local unprivileged user.
* Compromised LLM endpoint.
* Prompt injection through peer aliases or node metadata.
* Compromised Telegram destination.
* Malicious or malformed fixture.
* Stale or dishonest upstream node response.
* Dependency compromise.
* Disk corruption.
* Clock manipulation.
* Replayed events.
* Network partition.
* Operator misconfiguration.
* Future unsafe execution feature accidentally enabled.

### Required v1 invariants

At minimum, verify these invariants:

1. Rieko cannot spend funds.
2. Rieko cannot open, close or rebalance channels in v1.
3. Rieko cannot mutate Bitcoin Core or LND state in v1.
4. LLM output cannot create or elevate a finding.
5. Failure of the LLM cannot stop deterministic detection.
6. Replaying identical source data cannot create duplicate operational events.
7. Restarting Rieko cannot reset alert cooldown unexpectedly.
8. The status endpoint cannot claim healthy while ingestion is stale or dead.
9. Secrets cannot appear in logs, API responses or audit entries.
10. A remote web page cannot use a browser to control a localhost Rieko service.
11. Findings always retain the evidence and detector version that produced them.
12. Future simulation or execution types cannot become reachable accidentally in the v1 build.

## Runtime validation scenarios

Where the repository supports them, run or design reproducible tests for:

1. Fixture-based scan from a clean database.
2. Exact replay of the same fixture.
3. Modified fixture showing one legitimate state change.
4. Abrupt process termination during persistence.
5. Monitor and API server accessing the same SQLite database.
6. Missing LLM configuration.
7. LLM timeout.
8. Malformed LLM response.
9. Missing Telegram configuration.
10. Telegram timeout or HTTP failure.
11. LND authentication failure.
12. Invalid TLS certificate.
13. Wrong Bitcoin network.
14. Stale LND response.
15. Invalid or adversarial node alias.
16. Very large fixture.
17. Corrupt database.
18. Missing frontend assets.
19. Binding the API to a non-loopback address.
20. Attempting to reach any simulation or execution path.

Do not perform unsafe operations against a real node.

Use fixtures, mocks, test doubles or regtest where necessary.

## Required final deliverable

Produce one report with the following exact structure.

# 1. Executive verdict

Provide:

* Overall verdict.
* Current maturity level.
* Whether the v1 vertical slice is genuinely usable.
* Whether it is safe for controlled local testing.
* Whether it is safe for a real mainnet operator.
* The three strongest aspects.
* The five most serious risks.
* A clear recommendation: proceed, proceed with restrictions, or stop and harden.

# 2. Architecture conformance matrix

Create a table with one row for each ADR decision D1–D9.

Columns:

* Decision.
* Status: Compliant / Partial / Violated / Unverifiable.
* Repository evidence.
* Operational consequence.
* Required correction.

# 3. System map

Document the actual implementation:

* Crates.
* Dependency direction.
* Runtime components.
* Entry points.
* Data flow.
* Persistence flow.
* Alert flow.
* LLM flow.
* Frontend delivery.
* Simulation/execution reachability.

Clearly distinguish the implemented architecture from the intended architecture.

# 4. Findings register

For every material finding include:

* ID such as `RIEKO-AUDIT-001`.
* Concise title.
* Severity: Critical / High / Medium / Low / Informational.
* Confidence: High / Medium / Low.
* Category.
* ADR decision affected.
* Evidence with file paths and line references.
* Actual behaviour.
* Expected behaviour.
* Real operational impact.
* Exploit or failure scenario.
* Recommended remediation.
* Verification test.
* Estimated effort: S / M / L / XL.
* Blocking status for v1.

Severity definitions:

* Critical: credible risk of fund loss, credential compromise, unauthorized node mutation, or complete invalidation of operator trust.
* High: major security, correctness, durability or architecture failure that blocks safe real-node use.
* Medium: meaningful weakness that should be resolved before broad release.
* Low: limited-risk quality or maintainability issue.
* Informational: improvement or future consideration.

Do not inflate severity.

# 5. Verified strengths

List only strengths demonstrated by code or tests.

Do not list intentions, directory names or documentation as strengths unless implementation evidence supports them.

# 6. Test and CI gap matrix

For each critical capability show:

* Existing coverage.
* Missing coverage.
* Recommended test.
* Suitable CI job.
* Whether it blocks v1.

# 7. V1 scope-control verdict

List:

* Capabilities properly inside v1.
* Capabilities incomplete inside v1.
* Capabilities implemented prematurely.
* Capabilities that must be feature-gated or made unreachable.
* Capabilities that should remain interfaces only.

Give a specific verdict on `rieko-simulation` and `rieko-execution`.

# 8. Prioritized remediation roadmap

Organize work into:

## P0 — Safety and correctness blockers

Required before connecting Rieko to a real mainnet node.

## P1 — V1 vertical-slice completion

Required before a credible v1 alpha.

## P2 — Production hardening

Required before external operator testing.

## P3 — Post-v1 improvements

Useful but not required for the first release.

Each roadmap item must include:

* Objective.
* Exact affected areas.
* Dependencies.
* Acceptance criteria.
* Required tests.
* Estimated effort.
* Whether it should be one task or split into multiple tasks.

# 9. Recommended v1 release gates

Define measurable release gates, including at minimum:

* Architecture conformance.
* Deterministic detector independence from LLM.
* Least-privilege node access.
* Read-only enforcement.
* Idempotent replay.
* Persistent alert deduplication.
* Database migration and crash recovery.
* Self-observability.
* Secret redaction.
* API exposure safety.
* Full vertical-slice tests.
* Single-binary packaging.
* CI enforcement.
* Operator documentation.

Use pass/fail criteria, not general aspirations.

# 10. Suggested implementation plan

Provide a dependency-ordered implementation plan suitable for subsequent OpenCode agent execution.

Do not implement it yet.

Group related fixes into coherent work packages and specify:

* Work package name.
* Goal.
* Files or crates likely affected.
* Preconditions.
* Changes required.
* Tests required.
* Completion evidence.
* Risks.
* Whether an ADR amendment is required.

# 11. ADR amendments

Identify any places where ADR-0001 should be clarified without weakening its core principles.

Do not casually overturn accepted decisions.

Possible clarification areas include:

* Whether future simulation and execution crates may exist in the v1 workspace.
* Definition of “one binary.”
* Minimum macaroon permissions.
* Definition of “read-only.”
* Audit-log durability and immutability expectations.
* LLM privacy boundary.
* Status freshness semantics.
* Detector versioning.
* Frontend asset packaging.
* Supported Bitcoin and Lightning networks.

# 12. Final go/no-go checklist

End with a concise checklist showing:

* Safe for fixture-only development.
* Safe for regtest.
* Safe for local read-only mainnet observation.
* Safe for remote API exposure.
* Safe for unattended operation.
* Ready for v0.1.0-alpha.

Use:

* PASS
* CONDITIONAL
* FAIL
* NOT VERIFIED

## Audit quality rules

* Be direct and technically critical.
* Prefer a smaller number of well-proven findings over a large list of guesses.
* Trace execution paths instead of searching only for keywords.
* Verify README claims.
* Treat secrets and operator trust as first-class assets.
* Do not recommend microservices, Kubernetes, Redis, Kafka, PostgreSQL or cloud architecture without a demonstrated v1 requirement.
* Do not recommend AI or ML where deterministic rules are sufficient.
* Do not interpret “read-only” as safe merely because no obvious spend call is present.
* Do not mistake compile success for operational correctness.
* Do not mistake typed models for enforced state machines.
* Do not mistake an audit table write for an immutable audit trail.
* Do not mistake an HTTP `/status` response for meaningful self-observability.
* Do not describe placeholder simulation or execution modules as harmless until their reachability is traced.
* Keep recommendations consistent with the one-binary, self-hosted, SQLite-first architecture.
* Preserve Rieko’s core product principle: evidence first, explanation second, human authority always.
