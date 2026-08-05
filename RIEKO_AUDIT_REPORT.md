# Rieko — Architecture, Security and Production-Readiness Audit

Audit date: 2026-08-05
Repository: `https://github.com/comwanga/rieko.git` (checked out branch `lnd-executor`, HEAD `13089a3`)
Contract audited against: `docs/adrs/0001-rieko-v1-architecture.md` (ADR-0001)
Mode: read-only inspection + fixture-based runtime validation. No code was modified, no commits created.

Validation was performed by compiling/executing the workspace and running the real binary against
`fixtures/channels.json` (clean DB, exact replay, simulate, serve + HTTP, status). Commands run:
`cargo fmt --all -- --check` (PASS), `cargo check --workspace --all-targets --all-features` (PASS),
`cargo test --workspace --all-targets --all-features` (PASS, 51 tests), `cargo clippy --workspace
--all-targets --all-features -- -D warnings` (PASS), `cargo doc --workspace --no-deps` (PASS),
`cargo deny check advisories` (PASS), `cargo deny check licenses` (FAIL — no deny.toml exists),
`cargo deny check bans` (PASS). Frontend was inspected from `frontend/dist` (pre-built) and its
sources; `node` is not on the audit shell's PATH, so `npm run check/lint/test/build` could not be
re-executed — the committed build artifacts and `package.json` were inspected instead (see
RIEKO-AUDIT-017).

---

# 1. Executive verdict

**Overall verdict: STOP AND HARDEN.** This is a coherent, unusually well-layered vertical slice for a
two-week-old codebase, but it is not safe for a real mainnet operator, and it is not yet a correct
implementation of its own ADR. Two hard blockers exist: (1) a live-node, node-**mutating** execution
path is compiled into the v1 binary and reachable from the CLI (`actions execute --lnd-rest ...`),
directly contradicting the frozen "v1 stops at Recommend / read-only by default" contract; (2) the
engine has no idempotent persistence — replaying the same source data duplicates every finding,
recommendation and audit row, which is the exact failure ADR D9 and invariant #6 forbid.

**Maturity level:** early prototype / "demo slice". The scan pipeline works end to end against a
fixture and the code is clean (clippy/fmt/tests all green), but operational guarantees are absent.

**Is the v1 vertical slice genuinely usable?** Conditionally. `scan --fixture` is a working demo:
ingest → normalize → detect → store → recommend → audit, with optional LLM explanation and Telegram.
It is deterministic and works without any LLM. But it is not *correctly* usable: every scan appends
duplicate records, alert cooldown does not survive restart, and the DB has no schema version.

**Safe for controlled local testing?** Yes, on fixtures only, with the caveat that the DB accumulates
duplicates and the audit log records transitions that did not actually occur.

**Safe for a real mainnet operator?** No. Node mutation is reachable, macaroon/TLS handling for live
LND is broken (so live ingestion would fail anyway), the API is unauthenticated if bound off-loopback,
alert state is lost on restart, and no migration/rollback path exists.

**Three strongest aspects**
1. Detector purity and dependency direction are genuinely respected: `rieko-domain` depends on nothing
   internal, detectors are pure (`registry.rs:18-21`), ingest-lnd depends only on `rieko-domain`, and
   the recommendation engine consumes typed findings rather than rediscovering anomalies.
2. The LLM is a true add-on: `NullClient` is the default, `persist_and_recommend` degrades to the
   evidence dump on LLM absence/failure, and no detector path touches the LLM. Verified: clean run with
   no `RIEKO_LLM_*` env vars.
3. The single-binary, SQLite-only, no-broker deployment shape is real at the runtime level — one Rust
   process, WAL SQLite, Axum serving JSON + static files. No Node/Python/Redis/Kafka anywhere in prod.

**Five most serious risks**
1. Reachable node-mutating execution in the v1 binary (`actions execute` → `LndExecutor` → `PUT
   /v1/chanpolicy`) with no configuration gate, feature flag, or hard disable (RIEKO-AUDIT-001).
2. Non-idempotent persistence: identical replays create duplicate findings/recommendations/audit rows,
   corrupting any trend, alerting or audit reasoning (RIEKO-AUDIT-002, runtime-verified).
3. The documented live-node path is both unsafe (default `admin.macaroon`, no least-privilege story)
   and non-functional (self-signed LND cert not handled; binary macaroon read as a String)
   (RIEKO-AUDIT-003).
4. No schema versioning, no migration/rollback, no corruption strategy, and no busy-timeout — the
   durable layer is not upgradeable or crash-safe by design (RIEKO-AUDIT-005/006).
5. Self-observability is fictional: `/status` reports only DB row counts with a hardcoded `read_only`
   flag; it cannot claim meaningful health, and restart resets all alert cooldown (RIEKO-AUDIT-008).

**Recommendation: proceed with restrictions — but only after P0 items in §8 are implemented and
enforced. Do not connect to a real LND node until then.**

---

# 2. Architecture conformance matrix

| Decision | Status | Repository evidence | Operational consequence | Required correction |
|---|---|---|---|---|
| D1 Intelligence engine, not AI | **Compliant** | `rieko-llm` explains only; `NullClient` default (`client.rs:31-37`); detector pipeline never calls LLM; `persist_and_recommend` degrades (`common.rs:95-107`) | Engine fully functional without LLM | None |
| D2 Language-per-layer, one runtime | **Compliant** | Only Rust runtime crates; no Python/Node server; frontend built to static assets | One prod runtime | None at runtime; see D15 packaging gap (RIEKO-AUDIT-014) |
| D3 Frozen deployment shape / read-only | **Violated** | `LndExecutor::execute` → `update_chan_policy` → `PUT /v1/chanpolicy` (`execution/lnd.rs:27-50`, `ingest-lnd/client.rs:56-79`), reachable via `rieko actions execute` (`actions.rs:144-198`) | v1 binary can mutate a real LND node's fee policy | Remove/feature-gate execution; enforce read-only in v1 build |
| D4 Domain layer as the kernel | **Partial** | Pipeline `LND → Normalizer → Channel → Detector` is correct; but `Channel.liquidity` is computed from raw balances only — no reserves, pending HTLCs, or commit-fee semantics; forward-event channel ids cannot correlate to channel points (`normalize.rs:50-62`) | Domain semantics are a thin re-typing in places; correlations break | Model reserve/HTLC/legacy semantics; fix event channel id scheme |
| D5 Enforced dependency direction | **Compliant** (convention-only, not machine-enforced) | `domain`/`graph` kernels clean; detectors depend on domain+graph+findings only; no reverse deps into kernel; but no automated boundary check exists (CI has none) | Direction holds today; will rot silently | Add `cargo-deny`/`cargo-mutants`-style boundary job |
| D6 SQLite-first storage | **Partial** | WAL + foreign_keys ON (`sqlite.rs:21-22`), but no busy_timeout, no schema version, no transactions, no rollback, no corruption handling, no retention (RIEKO-AUDIT-006/011) | Not upgradeable, busy-race prone under concurrency, unbounded growth | Migrations, busy_timeout, retention |
| D7 Action model progression | **Violated** | v1 "must stop at Recommend" but Simulate (CLI `simulate`, API `/simulations`, UI tab) and Approve/Execute (CLI `actions`) are shipped, reachable, and node-mutating; audit stage diverges from real stage (RIEKO-AUDIT-012) | Operators get an execution control-plane that the ADR postponed | Gate behind explicit feature; stop at Recommend in v1 |
| D8 One vertical slice first | **Partial** | `LiquidityDetector` is first and functional; but `DriftDetector` (detector #2) shipped before the slice was hardened; simulate/execute added on top (see git log) | Second detector + execution added before slice proved | Harden slice; keep drift as experimental |
| D9 Non-negotiable constraints | **Violated** | Alert dedup in-memory only (`dedup.rs:13-42`); no idempotent persistence (RIEKO-AUDIT-002); `/status` has no freshness signal (RIEKO-AUDIT-008); rules-first detection is respected | Cooldown resets on restart; replays duplicate events; status claims health falsely | Persist dedup; add replay tests; real status |

---

# 3. System map (implemented vs intended)

Implemented architecture (verified in code):

```
crates/
  rieko-domain        kernel — nothing internal       [pure]
  rieko-graph         kernel — domain only             [in-memory HashMap + history deque]
  rieko-findings      domain + serde/uuid              [typed findings/actions/audit]
  rieko-storage       domain + findings + rusqlite     [SQLite behind trait; MemoryStorage for tests]
  rieko-ingest-lnd    domain + reqwest(blocking)       [wire types + normalizer]
  rieko-ingest-core   domain + serde                   [PLACEHOLDER — no RPC client]
  rieko-detectors     domain + graph + findings        [liquidity, drift]
  rieko-recommendations findings only                  [engine]
  rieko-simulation    domain + findings                [projection — shipped]
  rieko-execution     domain + findings + ingest-lnd   [LndExecutor — shipped, mutates node]
  rieko-alerts        findings + reqwest(blocking)     [Telegram + in-memory dedup]
  rieko-llm           findings + reqwest(blocking)     [OpenAI-compatible, NullClient default]
  rieko-api           storage + axum                   [8 read routes + static dir]
  rieko-cli           everything                       [scan/monitor/simulate/actions/status/serve]
```

Dependency direction: everything depends on `domain` and `findings`; no reverse edges; no cycles
(verified with `cargo tree`). Boundary enforcement is **convention-only** — nothing in CI checks it.

Runtime components (the one process):
- `rieko scan` — one-shot ingest→detect→recommend→explain→alert→persist (blocking, no async).
- `rieko monitor` — same in a loop with in-memory history + in-memory alert dedup; writes one
  `channel_snapshots` row per channel per cycle (blocking, single thread, `std::thread::sleep`).
- `rieko simulate` — re-runs the full pipeline, then projects rebalances; **also re-persists all
  findings/recommendations**, so it duplicates state every run.
- `rieko actions approve/reject/execute` — CLI-only control plane. `execute` with `--lnd-rest` uses
  `LndExecutor` and calls `PUT /v1/chanpolicy` on the live node.
- `rieko serve` — Axum, 8 GET routes, optional external `--static-dir`, storage behind
  `Arc<Mutex<Box<dyn Storage>>>`, blocking rusqlite on the async executor.
- `rieko status` — CLI dump of row counts.

Persistence flow: findings/recommendations/audit/simulations/snapshots/source_ledger → SQLite WAL.
Alert flow: finding → in-memory `DedupingSink` → Telegram (env-configured).
LLM flow: finding → prompt (evidence dump) → remote chat-completions → stored in `explanation` column.
Frontend delivery: **external** `frontend/dist` served by `ServeDir` — not embedded in the binary.
Simulation/execution reachability: **yes** — CLI subcommands, API `/simulations` route, UI tabs.

Implemented architecture vs intended: the workspace shape matches the ADR crate list plus
`rieko-simulation` and `rieko-execution`, both of which are shipped as reachable capabilities rather
than isolated interfaces (see §7).

---

# 4. Findings register

## RIEKO-AUDIT-001 — Node-mutating execution reachable in the v1 binary
- **Severity:** Critical · **Confidence:** High · **Category:** Scope control / D3 read-only / D7
- **ADR decision:** D3, D7, invariant #2/#3/#12
- **Evidence:** `crates/rieko-cli/src/commands/actions.rs:144-198` (`run_execute` builds the graph, reads
  the macaroon, and selects `LndExecutor` when `--lnd-rest` is set, lines 169-175);
  `crates/rieko-execution/src/lnd.rs:27-50` dispatches `ActionType::UpdateFeePolicy` to
  `update_chan_policy`; `crates/rieko-ingest-lnd/src/client.rs:56-79` sends `PUT /v1/chanpolicy`.
- **Actual behaviour:** `rieko actions execute <id> --actor human --lnd-rest https://<node> --macaroon admin.macaroon`
  pushes a fee-policy update (fee_rate_ppm/base_fee_msat/time_lock_delta) to a real LND node. There is
  no feature flag, no build-time exclusion, no confirmation prompt, and no config switch to disable
  execution. `RecordingExecutor` is only the fallback when no `--lnd-rest` is passed.
- **Expected behaviour:** v1 stops at Recommend (ADR D7). No code path in the v1 build may mutate LND,
  Bitcoin Core, config or system state. Execution must be unreachable (removed or feature-gated, absent
  from release builds).
- **Operational impact:** An operator following the README can inadvertently push fee changes to a live
  node — including the arbitrary `fee_rate_ppm: 1, base_fee_msat: 0` values the recommendation engine
  hardcodes (see RIEKO-AUDIT-010). This is unauthorized node mutation from a tool sold as read-only.
- **Exploit/failure scenario:** `rieko scan --lnd-rest ...` writes recommendations; later
  `rieko actions execute <id> --lnd-rest ... --actor me` mutates fee policy, possibly de-optimizing
  routing revenue or disabling inbound liquidity on the operator's own node.
- **Remediation:** Remove `rieko-execution`/`simulate` from the v1 binary (feature-gate), delete the
  `actions execute` route, or require a `--enable-execution` compile-time feature that v1 never enables.
- **Verification test:** assert that the release binary contains no `UpdateChanPolicy`-capable executor
  (e.g., `actions execute` returns "unavailable in v1 build"); assert no `PUT /v1/chanpolicy` string is
  reachable in the compiled graph.
- **Effort:** S · **Blocks v1:** Yes (P0)

## RIEKO-AUDIT-002 — Non-idempotent persistence: replays duplicate findings/recommendations/audit
- **Severity:** Critical · **Confidence:** High (runtime-verified) · **Category:** Idempotency/replay (D9, invariant #6)
- **ADR decision:** D9-2, invariant #6
- **Evidence:** `crates/rieko-detectors/src/liquidity.rs:83` (`id: Uuid::new_v4()` per finding per run);
  `crates/rieko-storage/src/sqlite.rs:138-157` (`INSERT OR REPLACE` keyed by that random id);
  `crates/rieko-findings/src/finding.rs:64-72` (`dedup_key` exists but is **never used** for persistence);
  `crates/rieko-cli/src/commands/common.rs:84-126` saves every finding unconditionally.
- **Actual behaviour (verified):** two consecutive `scan --fixture fixtures/channels.json` runs against
  one DB produced 6 findings, 8 recommendations and 8 audit entries (3 findings/4 recs/4 audit per run).
  Each run also creates a fresh `Action` id (`action.rs:62`). The source ledger (`source_ledger`,
  `sqlite.rs:75-78,365-392`) is written **nowhere** by scan/monitor — it is a dead abstraction.
- **Expected behaviour:** identical replays must produce zero new rows; the per-source last-seen ledger
  must be consulted and advanced; graph upserts and snapshots need explicit idempotency keys.
- **Operational impact:** every monitor cycle or CI replay silently doubles the findings/audit data,
  making severity counts, alerting, trend analysis and the audit trail meaningless over time.
- **Verification test:** seed DB, run scan twice with same fixture, assert findings/recs/audit counts
  unchanged. Blocking for v1.
- **Remediation:** deterministic finding identity (detector+entity+signature of evidence+window),
  `INSERT ... ON CONFLICT DO NOTHING` with that key, wire the source ledger into scan/monitor, and gate
  LLM-explain updates so they don't double rows.
- **Effort:** M · **Blocks v1:** Yes (P0)

## RIEKO-AUDIT-003 — Live LND path is unsafe and non-functional (macaroon + TLS)
- **Severity:** High · **Confidence:** High · **Category:** LND ingestion security/correctness
- **ADR decision:** D3, invariant #9
- **Evidence:** README:45-46 recommends `--macaroon admin.macaroon`;
  `crates/rieko-cli/src/commands/common.rs:32-34` reads the macaroon with `std::fs::read_to_string(...).trim()`
  (binary bytes → lossy String) and `crates/rieko-ingest-lnd/src/client.rs:46` sends it verbatim as the
  `Grpc-Metadata-macaroon` header (LND expects a **hex-encoded** macaroon); `client.rs:30-39` builds a
  rustls reqwest client with **no** `add_root_certificate`/`danger_accept_invalid_certs`, so the documented
  `https://localhost:8080` flow cannot validate LND's self-signed `tls.cert`.
- **Actual behaviour:** (a) the binary macaroon is corrupted into a UTF-8 string before transmission, so
  auth will fail; (b) even with a correct hex file, TLS verification fails against a self-signed LND cert;
  (c) `admin.macaroon` grants every capability, including the `UpdateChanPolicy` used by
  RIEKO-AUDIT-001. No least-privilege macaroon story, no doc of required permissions.
- **Expected behaviour:** read-only ingestion needs only `invoices:read`, `offchain:read`,
  `onchain:read`, `router:read`-style permissions; macaroon should be hex-decoded from the binary file;
  TLS should either pin LND's cert (`--tls-cert` + `add_root_certificate`) or use HTTP over loopback with
  an explicit documented warning.
- **Verification test:** wire mock asserting the header value equals hex(macaroon file bytes); start a
  self-signed TLS endpoint and confirm the client refuses → then accepts with `--tls-cert`.
- **Remediation:** least-privilege default, hex-encode macaroon, add TLS-cert option, document
  permissions, and stop recommending admin.macaroon.
- **Effort:** M · **Blocks v1:** Yes (P0)

## RIEKO-AUDIT-004 — Alert deduplication is in-memory only; restart resets cooldown
- **Severity:** High · **Confidence:** High · **Category:** Alerting (D9-1, invariant #7)
- **ADR decision:** D9-1, invariant #7
- **Evidence:** `crates/rieko-alerts/src/dedup.rs:10-46` keeps `last_sent: HashMap<String, Instant>` in
  RAM and returns Ok(()) on suppression; `crates/rieko-cli/src/commands/monitor.rs:86-87` keeps the
  `previous` severity map in RAM. Nothing alert-related is persisted.
- **Actual behaviour:** restarting the monitor (or any process crash) forgets every cooldown and the
  `previous` severity table; the same condition re-alerts immediately. The `source_ledger` table that
  could anchor this is never written.
- **Expected behaviour:** dedup/cooldown and last-seen severity must be persisted so a restart cannot
  reset alert state.
- **Verification test:** send alert, kill process, restart, send same dedup key within cooldown → must be
  suppressed.
- **Remediation:** persist alert state (per-key `last_sent`/severity) in SQLite; load on startup.
- **Effort:** S/M · **Blocks v1:** Yes (P0)

## RIEKO-AUDIT-005 — No schema versioning, migrations, or rollback
- **Severity:** High · **Confidence:** High · **Category:** Storage durability (D6)
- **ADR decision:** D6
- **Evidence:** `crates/rieko-storage/src/sqlite.rs:36-108` `migrate()` runs only `CREATE TABLE IF NOT
  EXISTS`; there is no `PRAGMA user_version`, no migration numbering, no ALTER path, no rollback logic.
- **Actual behaviour:** any future schema change is silently applied or skipped depending on partial
  state; there is no way to detect a mismatched schema; a DB created by a future version cannot be
  rejected. Upgrade/rollback behaviour does not exist.
- **Operational impact:** users cannot upgrade without risking unusable or silently-corrupted data.
- **Remediation:** a versioned migration table + ordered steps + pre-open schema check that refuses
  unknown/newer versions; test the migration path in CI.
- **Verification test:** open a v1-schema DB with v2 code → clean error; run migrations against a seeded
  DB and verify data preserved.
- **Effort:** M · **Blocks v1:** Yes (P1)

## RIEKO-AUDIT-006 — SQLite mis-operation: no busy_timeout, no transactions, no corruption handling
- **Severity:** High · **Confidence:** High · **Category:** Storage (D6), concurrency
- **ADR decision:** D6
- **Evidence:** `sqlite.rs:18-26` sets only WAL and foreign_keys; no `busy_timeout`, no `synchronous`
  decision, no `PRAGMA integrity_check`, no transaction wrapping around the multi-statement
  persist-and-recommend loop (`common.rs:84-126` writes finding, then recommendation, then audit as
  separate autocommit statements). `monitor` (a second process) writes snapshots while `serve` reads.
- **Actual behaviour:** concurrent monitor-write + serve-read, or two monitors, can hit `SQLITE_BUSY`
  instantly (default busy_timeout=0). A crash between the finding insert and the audit insert leaves a
  partially-recorded recommendation with no audit entry. No corruption detection exists.
- **Expected behaviour:** busy_timeout ≥5s, per-scan-cycle transactions with rollback, integrity checks,
  and explicit crash-recovery testing.
- **Verification test:** concurrent writer + reader stress; kill -9 mid-cycle then assert no
  half-written recommendation; `PRAGMA quick_check`.
- **Remediation:** busy_timeout, wrap cycle writes in a transaction, add corruption reporting.
- **Effort:** S/M · **Blocks v1:** Yes (P1)

## RIEKO-AUDIT-007 — Audit trail is not tamper-evident and diverges from real state
- **Severity:** High · **Confidence:** High (runtime-verified) · **Category:** Auditability (D7, G)
- **ADR decision:** D7
- **Evidence:** `crates/rieko-cli/src/commands/simulate.rs:90-99` appends an audit entry with
  `stage: ActionStage::Simulated` but never calls `set_action_stage`; verified at runtime — after
  `simulate`, `status` shows 8 recommendations at `Recommended`, 0 `Simulated`, while the audit log
  contains 4 "Simulated" entries. `crates/rieko-storage/src/sqlite.rs:307-324` appends audit rows, but
  nothing prevents `UPDATE`/`DELETE` via the CLI or direct DB access; no hash chain.
- **Actual behaviour:** the audit log claims a transition the state machine never took; and entries are
  freely rewritable/deletable. The "immutable audit trail" claim (README, D7) is false.
- **Operational impact:** operators cannot trust the audit log for approvals/executions; post-hoc edits
  are invisible.
- **Remediation:** audit entries must reflect the actual persisted stage transition, and either be
  append-only at the DB layer (triggers denying UPDATE/DELETE) with a hash-chain or at minimum a
  documented, verifiable append-only guarantee.
- **Verification test:** after `simulate`, assert the recommendation stage and its last audit entry
  stage match; attempt an SQL UPDATE on `audit` and assert rejection.
- **Effort:** M · **Blocks v1:** Yes (P1)

## RIEKO-AUDIT-008 — `/status` is not self-observability; claims read-only unconditionally
- **Severity:** High · **Confidence:** High · **Category:** Self-observability (D9-3, invariant #8)
- **ADR decision:** D9-3, invariant #8
- **Evidence:** `crates/rieko-api/src/routes.rs:10-68` — status returns only counts derived from
  `latest_findings(1_000_000)`, `recent_audit(1_000_000)`, etc., and sets `read_only: true` literally
  (`routes.rs:57`). No ingestion freshness, no last-cycle time, no source connectivity, no LLM/alert
  health, no build commit, no degraded mode. The CLI `status` (`commands/status.rs:14-78`) is also
  count-only.
- **Actual behaviour:** an API server with zero connectivity to LND, zero detector cycles run, and a
  stale DB reports HTTP 200 "healthy" (verified). It says `read_only: true` even when the binary can
  mutate LND (RIEKO-AUDIT-001).
- **Expected behaviour:** status must report last successful/attempted ingestion, last detector cycle,
  source freshness, process uptime, and a degraded flag — never "healthy" merely because HTTP works.
- **Verification test:** run `serve` with an empty/stale DB; assert status exposes `last_ingest_at`,
  `last_cycle_at`, `source_connected` and a `degraded` boolean.
- **Remediation:** persist and expose operational timestamps; remove the hardcoded `read_only` claim.
- **Effort:** M · **Blocks v1:** Yes (P1)

## RIEKO-AUDIT-009 — "Single binary" not delivered: external `frontend/dist` required at runtime
- **Severity:** High · **Confidence:** High · **Category:** Deployment (D2/D3)
- **ADR decision:** D2, D3
- **Evidence:** `crates/rieko-api/src/app.rs:46-55` serves `frontend/dist` at runtime via `ServeDir`
  (not embedded); `frontend/.gitignore` excludes `dist/`; `.github/workflows/ci.yml:33-52` builds the
  frontend in a separate job and **never** packages it with the Rust binary; README:76-78 tells operators
  to build the frontend and pass `--static-dir frontend/dist`.
- **Actual behaviour:** the binary cannot be copied to a clean operator machine and serve the UI without
  a separately-built `dist` directory beside it. When assets are absent, the server 404s silently rather
  than failing loudly.
- **Expected behaviour:** assets embedded at compile time (or a release pipeline that produces one
  artifact), plus a clear failure if assets are missing.
- **Remediation:** embed `dist/` via `include_bytes!`/`rust-embed` with a build step, or produce a
  release archive containing binary+dist; document the true requirement.
- **Verification test:** build release, copy only the binary to an empty dir, run `serve` → UI loads.
- **Effort:** S/M · **Blocks v1:** Yes (P2)

## RIEKO-AUDIT-010 — Recommendation engine emits unsafe, hardcoded, overconfident advice
- **Severity:** High · **Confidence:** Medium · **Category:** Recommendation quality (workstream 10)
- **ADR decision:** D7 (v1 recommendations must be trustworthy)
- **Evidence:** `crates/rieko-recommendations/src/engine.rs:46-93` hardcodes `desired_ratio: 0.5`,
  `fee_rate_ppm: 1`, `base_fee_msat: 0`, `cltv_delta: 40`, and free-text "method": "splice-in or
  payment-rebalance" / "splice-out" from a single evidence value (`direction`), regardless of channel
  size, node role, routing strategy, or fee context. It never states preconditions, expected effect,
  risk or trade-offs, and presents the fee drop as a concrete actionable operation.
- **Actual behaviour:** every drained channel gets the same 50/50 rebalance advice and an aggressive fee
  cut (1 ppm / 0 base) that could destroy routing revenue; recommendations cannot be audited as to why
  those specific numbers were chosen.
- **Expected behaviour:** recommendations must express preconditions, expected effect, risk, and
  uncertainty; hardcoded fee values should be removed or derived from evidence; a drained channel should
  not automatically imply "rebalance now."
- **Operational impact:** an operator trusting Rieko could set 1-ppm fees on busy channels, losing income
  or, combined with RIEKO-AUDIT-001, actually do so.
- **Remediation:** add preconditions/risk fields to `Action`; derive parameters from evidence; gate
  execution-adjacent recommendations behind explicit operator config.
- **Effort:** M · **Blocks v1:** Yes (P1)

## RIEKO-AUDIT-011 — Liquidity domain model ignores reserves, HTLCs, commit fees; detector treats imbalance as harmful
- **Severity:** Medium · **Confidence:** High · **Category:** Domain model (D4), detector correctness
- **ADR decision:** D4
- **Evidence:** `crates/rieko-domain/src/channel.rs:59-82` computes `local_ratio = local/capacity` with
  no reserve, dust, pending-HTLC, or anchor/commit-fee deduction; `local_balance > capacity` yields
  `ratio > 1.0` which falls into `r > 0.97 => SeverelyDrained` (an inverted/absurd classification);
  `crates/rieko-ingest-lnd/src/model.rs:8-22` doesn't read `pending_htlcs`/reserve fields;
  `normalize.rs:41-44` sets `fee_policy: FeePolicy::default()` because LND's actual policy isn't fetched;
  `crates/rieko-detectors/src/liquidity.rs:51-102` flags any non-balanced ratio as a Warning/Critical
  anomaly with no node-role/intent context.
- **Actual behaviour:** a channel with 12% local ratio on a deliberate one-way routing strategy is
  flagged as a warning and told to rebalance; spendable capacity (after reserve) is misreported.
- **Expected behaviour:** the domain model must carry reserve-adjusted spendable liquidity, pending
  HTLCs and fee policy as first-class fields; imbalance must be a signal, not automatically a problem.
- **Remediation:** extend `Channel`/`LiquidityProfile`, feed real fee policy from `/v1/graph/edges` or
  per-channel policy, add role/config context.
- **Effort:** M · **Blocks v1:** P1 (partial), P3 (full)

## RIEKO-AUDIT-012 — Findings are unstable: random IDs, no schema version, no detector version, no lifecycle
- **Severity:** Medium · **Confidence:** High · **Category:** Findings/evidence model (workstream 9)
- **ADR decision:** D9
- **Evidence:** `finding.rs:43-54` — `Finding` has no schema version, no detector version, no
  observation window, no confidence, no lifecycle/resolution field; `dedup_key` (lines 64-72) is unused
  for storage; IDs are `Uuid::new_v4()` per run (RIEKO-AUDIT-002); `row_to_finding`
  (`sqlite.rs:110-134`) silently turns corrupt evidence JSON into an empty vec and bad timestamps into
  `Utc::now()`.
- **Actual behaviour:** an operator cannot tell whether two rows are the same finding, which detector
  version produced a finding, or whether a finding recurred or resolved. Corrupt data is silently
  misloaded.
- **Expected behaviour:** stable finding identity + schema/detector versions + window + lifecycle;
  fail loudly on corrupt rows.
- **Remediation:** add schema_version/detector_version/window/confidence/resolved fields; deterministic
  identity; strict deserialization.
- **Effort:** M · **Blocks v1:** P1

## RIEKO-AUDIT-013 — Telegram sink: no timeout, retry, truncation, or escaping; Markdown injection surface
- **Severity:** Medium · **Confidence:** High · **Category:** Alerting (workstream 12)
- **ADR decision:** D9-1
- **Evidence:** `crates/rieko-alerts/src/telegram.rs:21,40-67` — `reqwest::blocking::Client::new()` with
  no timeout (a hung Telegram can block scan forever); message text is built by
  `format!("{emoji} *{title}*...{message}...` with `parse_mode: "Markdown"` and untrusted channel/peer
  strings interpolated unescaped; no truncation for long messages.
- **Actual behaviour:** a peer pubkey or channel id containing `*`/`_`/`[` can break formatting or cause
  Telegram to reject the request (or inject markdown); a stuck Telegram endpoint stalls the scan loop.
- **Remediation:** timeout, retry/backoff, escape or strip markdown metacharacters, truncate to 4096,
  and non-blocking send.
- **Effort:** S · **Blocks v1:** P2

## RIEKO-AUDIT-014 — API has no auth, CORS/CSRF/trusted-host controls, security headers, or request limits
- **Severity:** Medium (High if bound off-loopback) · **Confidence:** High · **Category:** API/web
  security (invariant #10)
- **ADR decision:** D3
- **Evidence:** `crates/rieko-api/src/app.rs:46-83` — no middleware layer at all; `serve.rs:15-16`
  defaults to `127.0.0.1:8080` but accepts any `--addr`; routes return raw JSON with no CSP,
  X-Frame-Options, Referrer-Policy, or cache headers (verified via curl: only content-type/length/date);
  `routes.rs:35-39` loads up to 1,000,000 rows per `/status` request inside a `std::sync::Mutex` on the
  async executor (blocking the Tokio runtime and holding the storage lock during full-table scans);
  no request-body/query limits beyond a hard clamp `1..=500` for list routes; no rate limiting; no auth.
- **Actual behaviour:** a browser on the same machine could `fetch("http://127.0.0.1:8080/status")` from
  any webpage (no CORS preflight block for simple GETs; a malicious site can read node topology);
  binding `0.0.0.0` exposes all topology/history unauthenticated; a slow `/status` blocks other requests.
- **Expected behaviour:** v1 binds loopback by default and warns loudly otherwise; add permissive-CORS
  only for same-origin, plus security headers, request limits, and a non-blocking storage handle.
- **Remediation:** loopback binding guard, header middleware, `tokio::task::spawn_blocking` for DB,
  auth (token) if exposed beyond loopback.
- **Effort:** M · **Blocks v1:** P2

## RIEKO-AUDIT-015 — CLI execution lacks a confirmation gate; actor is an unauthenticated string
- **Severity:** Medium · **Confidence:** High · **Category:** CLI security (workstream 14)
- **ADR decision:** D7
- **Evidence:** `crates/rieko-cli/src/commands/actions.rs:144-198` — `execute` takes `--actor` as a free
  string and runs immediately with no interactive confirmation; `transition` (`execution/lib.rs:59-65`)
  treats any non-empty, non-"system" string as a valid human. `RecordingExecutor` is the only safe
  default.
- **Actual behaviour:** any shell user can approve and execute actions by typing `--actor whatever`;
  "human approval" is purely nominal.
- **Expected behaviour:** real authentication/authorization (e.g., config-gated actors), interactive
  confirmation, and confirmation of the exact mutation before execution.
- **Remediation:** remove execution from v1 (see RIEKO-AUDIT-001); if kept, add an actor allow-list and
  a confirm prompt.
- **Effort:** S · **Blocks v1:** P0 via RIEKO-AUDIT-001

## RIEKO-AUDIT-016 — Snapshot/event storage is unbounded (no retention/compaction)
- **Severity:** Medium · **Confidence:** High · **Category:** Storage (D6, workstream 6)
- **ADR decision:** D6
- **Evidence:** `monitor.rs:105-110` writes one `channel_snapshots` row per channel per cycle;
  `sqlite.rs:80-91` defines no retention policy and the table has no pruning; `graph`/`InMemoryHistory`
  (`history.rs:18-53`) bounds history but forwards/payments are unbounded `Vec`s (`store.rs:51-53`);
  closed channels are never removed from the snapshot table.
- **Actual behaviour:** on a large node with 500 channels at a 60s interval, ~720k rows/day accumulate
  forever; `/snapshots` and `/status` grow monotonically and storage grows without bound.
- **Remediation:** retention window + compaction, prune closed-channel snapshots, bound in-memory
  event buffers.
- **Effort:** M · **Blocks v1:** P2

## RIEKO-AUDIT-017 — CI enforces none of the security/quality gates and no release pipeline exists
- **Severity:** Medium · **Confidence:** High · **Category:** CI/CD (workstream 19)
- **ADR decision:** D9
- **Evidence:** `.github/workflows/ci.yml` — only fmt/clippy/test/build (rust) and `npm run build`
  (frontend, no `check`/`lint`/`test` because `package.json` defines none); no `cargo audit`/`deny`,
  no license check, no MSRV check, no architecture-boundary check, no migration/fixture/replay tests, no
  regtest, no release/single-binary packaging, no dependabot, no CODEOWNERS, no SECURITY.md, actions
  pinned to mutable `@v4`/`@v2` tags (not SHAs). No `deny.toml` exists (`cargo deny check licenses`
  FAILED).
- **Actual behaviour:** the exact failure modes RIEKO-AUDIT-002/005/008 are introduced/regressed with no
  CI signal. No release artifact is produced.
- **Remediation:** add audit/license/boundary/replay/migration jobs, `npm run check`, MSRV check,
  dependabot, SECURITY.md, and a release job producing the packaged artifact (see RIEKO-AUDIT-009).
- **Effort:** M · **Blocks v1:** P2

## RIEKO-AUDIT-018 — Bitcoin Core support is scaffolding only; claims outrun code
- **Severity:** Medium · **Confidence:** High · **Category:** Ingest (workstream 5), docs
- **ADR decision:** D4/D8
- **Evidence:** `crates/rieko-ingest-core/src/lib.rs:1-7` explicitly states the crate "exists to fix the
  workspace shape"; `blocks.rs` is a JSON normalizer with a unit test; there is no Core RPC client, no
  network/chain verification, no IBD/prune handling, no cookie auth, no ZMQ. The v1 detector never
  consumes Core data.
- **Actual behaviour:** "Bitcoin Core ingestion" is a placeholder. Core is correctly excluded from the
  v1 slice, but the workspace and docs imply a capability that does not exist.
- **Remediation:** document Core as out-of-scope for v1 (ADR already does); keep crate as isolated
  interface or remove from the workspace until implemented.
- **Effort:** S · **Blocks v1:** No (documentation fix only)

## RIEKO-AUDIT-019 — Forward/payment event normalization is incorrect (channel id mismatch, fabricated timestamps)
- **Severity:** Medium · **Confidence:** High · **Category:** Ingest/domain correlation
- **ADR decision:** D4
- **Evidence:** `crates/rieko-ingest-lnd/src/normalize.rs:50-62` builds `ForwardEvent.id` from
  `chan_id_in|chan_id_out|timestamp|fee_msat` (not unique), sets `timestamp: Utc::now()` instead of the
  LND `timestamp`, and uses raw LND `chan_id` (a short-channel-id number) as `ChannelId` while channels
  are keyed by `chan_point` (`normalize.rs:27`). The detector never uses forwards, so the inconsistency
  is latent.
- **Actual behaviour:** forwarding events cannot be correlated to any channel; event ids can collide;
  dedup is impossible; timeline timestamps are wrong.
- **Remediation:** resolve chan_id↔chan_point mapping, use the source timestamp, build a unique id.
- **Effort:** S/M · **Blocks v1:** P2

## RIEKO-AUDIT-020 — The graph is a thin HashMap wrapper ("graph theatre" risk)
- **Severity:** Low · **Confidence:** Medium · **Category:** Graph (workstream 7)
- **ADR decision:** D4
- **Evidence:** `crates/rieko-graph/src/store.rs:70-143` — `InMemoryGraph` is a HashMap keyed by id with
  `channels_for_peer` linear scans; detectors consume `view.channels()` directly
  (`liquidity.rs:53`, `drift.rs:65`), so no traversal/analysis actually uses graph structure; nodes for
  peers are auto-created with `NodeStatus::Unknown` (`store.rs:107-115`); stale/closed entities are
  never removed; graph state is never persisted (only snapshots are).
- **Actual behaviour:** the graph abstraction currently adds no analytical value beyond a collection
  layer and can diverge from persisted state; the "graph" in the ADR's pipeline diagram is nominal.
- **Remediation:** either implement real graph capabilities the detectors use, or document the graph as
  a future kernel and keep it minimal. Not a v1 blocker.
- **Effort:** M · **Blocks v1:** No

## RIEKO-AUDIT-021 — `status_from_flags` semantics unverified; malformed channel data can silently produce wrong state
- **Severity:** Low · **Confidence:** Medium · **Category:** Normalizer robustness
- **ADR decision:** D4
- **Evidence:** `crates/rieko-ingest-lnd/src/normalize.rs:65-77` maps `chan_status_flags` with a
  `parse::<u32>().unwrap_or(0)` — any malformed flag string becomes `Active`; `0` is `Active`, `2` is
  `ForceClosing`, `4` is `Inactive`, everything else `Active`. Fixture `999000111222333444:0` has flags
  `"2"` (ForceClosing) and is skipped by detectors — plausible but no test proves the mapping matches
  LND semantics across LND 0.17+.
- **Actual behaviour:** an unrecognized flag bit (e.g., `8`) silently reports an active, healthy channel,
  or a stale channel is treated as open.
- **Remediation:** treat unknown flag combinations as a distinct/unknown state; add a mapping table with
  tests referencing LND's channel_status_flags.
- **Effort:** S · **Blocks v1:** P2

## RIEKO-AUDIT-022 — Simulate re-runs detection and duplicates the whole slice (compounding RIEKO-AUDIT-002)
- **Severity:** Medium · **Confidence:** High (runtime-verified) · **Category:** Scope/simulation
- **ADR decision:** D7
- **Evidence:** `crates/rieko-cli/src/commands/simulate.rs:57-68` runs the same pipeline and persists
  findings/recommendations again before projecting. Verified: after `simulate`, findings=6 and
  recommendations=8 on a fresh DB that already had 3/4.
- **Actual behaviour:** running `simulate` is not "read-only what-if" — it doubles the persisted state
  and injects "Simulated" audit rows that don't correspond to real transitions (see RIEKO-AUDIT-007).
- **Remediation:** simulations must consume existing findings/recommendations from the DB without
  re-running detection, or be removed from v1.
- **Effort:** S · **Blocks v1:** P1

---

# 5. Verified strengths

1. **Clean dependency kernel** — `rieko-domain` imports only serde/thiserror/chrono; `rieko-graph`
   depends on domain only; detectors depend only on domain+graph+findings (Cargo.toml + cargo tree).
   No cycles, no reverse edges, no protocol SDK leakage into the domain.
2. **Deterministic, LLM-independent detection** — detectors are pure functions over a read-only graph
   view (`registry.rs:18-21`); the full scan works without any `RIEKO_LLM_*` env var; `NullClient`
   default; LLM errors are caught and degrade to evidence dumps (`common.rs:95-107`).
3. **Real typed action model with enforced legal transitions** — `transition`/`can_transition`
   (`execution/lib.rs:31-64`) rejects illegal stage moves and `system` self-approval; unit-tested
   (9 tests in `rieko-execution`).
4. **Single runtime, no brokers** — SQLite WAL behind a trait, one Rust binary, no Redis/Kafka/PG/Node
   in production paths.
5. **Idempotent graph upsert semantics** — `upsert_channel` keyed by channel id replaces cleanly
   (`store.rs:106-118`, unit-tested), satisfying part of D9.
6. **Quality gates pass** — `cargo fmt --check`, `cargo clippy -D warnings`, and all 51 tests green;
   `cargo deny advisories` and `bans` clean; no `unsafe` code; no git dependencies in the lockfile.
7. **Honest failure of the rebalance executor** — `LndExecutor` refuses `RebalanceChannel` loudly
   (`execution/lnd.rs:43-45`), which is exactly the right stance for v1.
8. **Read-only default executor** — `RecordingExecutor` is the safe default when no `--lnd-rest` is
   given (`actions.rs:169-175`).

---

# 6. Test and CI gap matrix

| Capability | Existing coverage | Missing coverage | Recommended test | CI job | Blocks v1 |
|---|---|---|---|---|---|
| Normalizer correctness (LND→domain) | 3 unit tests | HTLCs, reserves, fee policy, status flags across LND versions, adversarial payloads | Fixture-driven normalization matrix incl. malformed/negative/oversized values | rust | P1 |
| Idempotent replay | none (graph upsert only) | scan×2 on same DB must not grow | Replay test on SQLite (2 identical scans == 0 new rows) | rust | P0 |
| Finding stability | none | same input → same dedup identity | Golden finding-set test | rust | P1 |
| Alert dedup persistence | in-memory unit tests only | restart must not reset cooldown | Kill/restart test asserting suppression | rust (integration) | P0 |
| DB migration | none | v1→v2 schema, rollback | Migration test with seeded DB | rust | P1 |
| LLM failure | null-client test | timeout/malformed response mid-scan | Mock HTTP 500/garbage endpoint; assert engine continues | rust | P1 |
| Telegram failure | none | timeout/HTTP error non-blocking | Mock sink failing; assert scan completes | rust | P2 |
| Read-only guarantee | none | no mutation reachable in v1 build | Binary-level assert: no chanpolicy path when feature-gated | rust | P0 |
| Simulation/execution isolation | unit tests on `project`/`transition` | CLI reachability & no node mutation | CLI test using RecordingExecutor only | rust | P1 |
| API limits & auth | 3 route tests (status/snapshots/simulations) | off-loopback guard, headers, request limits | HTTP integration incl. CORS/header assertions | rust | P2 |
| Concurrent monitor+API on one DB | none | SQLITE_BUSY under write+read | Two-process WAL stress test | rust (integration) | P1 |
| Corrupt/adversarial fixture | partial (bad chan_point, missing height) | unknown fields, wrong network, huge sets | Fuzz/edge fixture suite | rust | P2 |
| Very large channel sets | none | memory/latency on 1000s of channels | Bench/fixture with 10k channels | rust (nightly bench) | P3 |
| Regtest/live-node integration | none | real LND payloads | Regtest harness with real LND REST | rust (integration, opt-in) | P2 |
| Frontend | build only | `npm run check`/`lint`/`test` (scripts absent), API contract | svelte-check + vitest on api.ts | frontend | P2 |

---

# 7. V1 scope-control verdict

- **Inside v1 (working):** `scan` (fixture), `serve` read API, `status`, SQLite persistence, liquidity
  detection, typed recommendations, optional LLM explain, optional Telegram alert (single-binary runtime).
- **Incomplete inside v1:** idempotency/replay (RIEKO-AUDIT-002), alert persistence (004), migrations
  (005), self-observability (008), single-binary packaging (009), recommendation quality (010).
- **Implemented prematurely:** `DriftDetector` (detector #2 before slice hardened — ADR D8);
  **`rieko-simulation`** (D7 v2) and **`rieko-execution`** (D7 v3) shipped and reachable; the whole
  `actions` CLI; the `/simulations` API route; the Simulations/Actions/Audit UI tabs.
- **Must be feature-gated or made unreachable in v1:** `rieko-execution` entirely (node mutation) and
  `rieko-simulation` (or made DB-read-only, RIEKO-AUDIT-022).
- **Should remain interfaces only:** `rieko-simulation` projection model, `Executor` trait —
  keep the *types* for the D7 contract, but no reachable CLI/API path in the v1 build.

**Verdict on `rieko-simulation`:** it is a legitimate, deterministic, read-only projection *library*
(D7 v2), but its CLI command is premature (re-runs detection and duplicates state) and its API/UI
exposure ships v2 capability in a v1 binary. Keep the crate as an isolated interface; gate the CLI/API.

**Verdict on `rieko-execution`:** **violation of the v1 boundary.** A node-mutating executor is compiled
into the v1 binary and reachable via the CLI. Remove the reachable path (and its CLI/API) from v1;
retain only the transition/enum types and the `RecordingExecutor` for the D7 contract. Do not keep
`LndExecutor` reachable under any flag in a v1 build.

---

# 8. Prioritized remediation roadmap

## P0 — Safety and correctness blockers (before any real-node connection)

1. **RIEKO-AUDIT-001 — Disable execution in v1.** Remove `actions execute`+`LndExecutor` from the build
   (feature-gate behind `--features execution` never enabled in v1, or delete). Affected:
   `rieko-execution/lnd.rs`, `rieko-cli/commands/actions.rs`, `rieko-api` if any route is added. Tests:
   assert v1 binary has no `UpdateChanPolicy` reachable path. Effort S.
2. **RIEKO-AUDIT-002 — Deterministic, idempotent persistence.** Add stable finding identity
   (detector+entity+evidence signature+window), `ON CONFLICT DO NOTHING`, wire the `source_ledger` into
   scan/monitor, and make LLM-explain update-in-place rather than insert. Affected: `rieko-findings`,
   `rieko-detectors`, `rieko-storage/sqlite.rs`, `rieko-cli/common.rs`. Tests: double-scan replay on
   SQLite must not grow. Effort M.
3. **RIEKO-AUDIT-003 — Fix LND auth/TLS.** Hex-encode macaroon, add `--tls-cert` + root-cert pinning,
   document least-privilege macaroon, remove admin.macaroon default. Affected: `rieko-ingest-lnd/client.rs`,
   `common.rs`, README. Tests: mock asserting hex header; self-signed TLS accept/refuse. Effort M.
4. **RIEKO-AUDIT-004 — Persist alert dedup.** Store per-key last-sent/severity in SQLite; load at
   startup. Affected: `rieko-alerts/dedup.rs`, `rieko-storage`, `monitor.rs`. Test: restart within
   cooldown must suppress. Effort S/M.

## P1 — Vertical-slice completion (credible v1 alpha)

5. **RIEKO-AUDIT-005/006 — Migration framework + SQLite operation.** `user_version`-based migrations,
   `busy_timeout`, per-cycle transactions, integrity checks. Tests: migration + crash recovery. Effort M.
6. **RIEKO-AUDIT-007/012 — Audit integrity + finding lifecycle.** Audit entries must reflect real
   transitions; append-only enforcement; add finding schema/detector versions, window, resolution.
   Effort M.
7. **RIEKO-AUDIT-008 — Real self-observability.** Persist last-ingest/last-cycle/source status; report
   them in `/status` and CLI `status`; remove hardcoded `read_only`. Effort M.
8. **RIEKO-AUDIT-010 — Recommendation quality.** Add preconditions/expected-effect/risk fields; derive
   parameters from evidence; remove hardcoded fee values. Effort M.
9. **RIEKO-AUDIT-022 — Simulate must not re-run the slice.** Consume persisted findings/recs; no new
   rows. Effort S.

## P2 — Production hardening (external operator testing)

10. **RIEKO-AUDIT-009 — Embed frontend** (rust-embed/include_bytes) or release-packaged artifact. Effort S/M.
11. **RIEKO-AUDIT-013/014 — Telegram + API hardening.** Timeouts/retries/escaping/truncation; loopback
    guard, security headers, `spawn_blocking` DB, request limits, optional token auth. Effort M.
12. **RIEKO-AUDIT-016 — Retention/compaction** for snapshots; bound event buffers. Effort M.
13. **RIEKO-AUDIT-017 — CI gates.** cargo-deny (advisories+licenses+boundaries), migration/replay/fixture
    tests, `npm run check`, dependabot, SECURITY.md, release packaging job. Effort M.
14. **RIEKO-AUDIT-019/021 — Normalizer fixes** (forward id/timestamp/chan-id mapping; flag semantics). Effort S/M.
15. **Regtest harness** for LND ingestion with real payloads. Effort L (split into 2 tasks).

## P3 — Post-v1 improvements

16. **RIEKO-AUDIT-011 — Full liquidity semantics** (reserves, HTLCs, fee policy, role-aware detection). Effort L.
17. **RIEKO-AUDIT-020 — Real graph analytics or de-scope.** Effort M.
18. Status/build metadata (git commit in version), signal handling/graceful shutdown, frontend tests. Effort S/M.

---

# 9. Recommended v1 release gates (pass/fail)

1. **Architecture conformance:** release binary contains no reachable execution/simulation path;
   `rieko-execution/lnd.rs` and `actions execute` absent or feature-off. PASS required.
2. **Deterministic detector independence from LLM:** `scan --fixture` with `RIEKO_LLM_*` unset and with a
   dead/malformed LLM endpoint yields identical findings; findings unchanged. PASS required.
3. **Least-privilege node access:** README + CLI require a scoped read-only macaroon; no admin.macaroon
   anywhere in docs. PASS required.
4. **Read-only enforcement:** no code path can call LND/Core mutation in the v1 build (grep-gated in CI). PASS required.
5. **Idempotent replay:** two identical scans against one DB produce 0 new findings/recs/audit rows. PASS required.
6. **Persistent alert deduplication:** kill/restart within cooldown does not re-alert. PASS required.
7. **DB migration + crash recovery:** migration test and kill-9 mid-cycle leaves no half-written rows. PASS required.
8. **Self-observability:** `/status` reports last-ingest, last-cycle, source status, degraded flag. PASS required.
9. **Secret redaction:** grep logs/API for macaroon/token/key after a live scan; none. PASS required.
10. **API exposure safety:** `serve` refuses non-loopback binds without explicit override + warning;
    security headers present. PASS required.
11. **Full vertical-slice tests:** end-to-end fixture test asserting the whole pipeline and its counts. PASS required.
12. **Single-binary packaging:** release job produces one runnable artifact with embedded assets. PASS required.
13. **CI enforcement:** fmt/clippy/tests/audit/licenses/replay/migration all enforced. PASS required.
14. **Operator documentation:** README matches CLI (commands verified), documents privacy, permissions,
    local-only mode, limitations, backup/upgrade. PASS required.

---

# 10. Suggested implementation plan (dependency-ordered)

- **WP1 — Read-only enforcement (P0).** Goal: no node mutation reachable. Files: `crates/rieko-cli/src/commands/actions.rs`,
  `crates/rieko-execution/src/lnd.rs`, `Cargo.toml` (feature flags), CI. Preconditions: none.
  Changes: feature-gate/remove execution; keep types. Tests: binary-level no-mutation assert.
  Completion evidence: `actions execute` returns "unavailable"; CI grep gate. Risks: minimal.
  ADR amendment: clarify "one binary" vs feature flags.
- **WP2 — Idempotent persistence (P0).** Depends on WP1 (same files touched for findings). Files:
  `rieko-findings`, `rieko-detectors/liquidity.rs`, `rieko-storage/sqlite.rs`, `rieko-cli/common.rs`.
  Completion evidence: double-scan replay test green.
- **WP3 — LND connectivity (P0).** Files: `rieko-ingest-lnd/client.rs`, `common.rs`, README, new
  `--tls-cert` arg, hex macaroon. Completion evidence: mock + self-signed TLS tests green.
- **WP4 — Alert persistence (P0).** Files: `rieko-alerts/dedup.rs`, `rieko-storage`, `monitor.rs`.
- **WP5 — Migrations + SQLite ops (P1).** Depends on WP2 (storage layer stability). Files:
  `rieko-storage/sqlite.rs`.
- **WP6 — Audit integrity + finding lifecycle (P1).** Depends on WP2/WP5.
- **WP7 — Self-observability (P1).** Files: `rieko-api/routes.rs`, `rieko-storage`, `status.rs`.
- **WP8 — Recommendation quality (P1).** Files: `rieko-recommendations/engine.rs`, `rieko-findings/action.rs`.
- **WP9 — Simulate isolation (P1).** Depends on WP2/WP6.
- **WP10 — Single-binary packaging + CI gates (P2).** Depends on WP5/WP7.
- **WP11 — API/Telegram hardening (P2).**
- **WP12 — Retention + normalizer fixes + regtest (P2).**
- **WP13 — Liquidity semantics (P3).**

All work packages: each includes unit + integration tests, and a CI job; completion evidence is a
passing CI run plus the specific test named in §9.

---

# 11. ADR amendments (clarifications, not weakenings)

1. **Definition of "one binary."** Clarify whether the frontend is embedded at compile time or shipped
   as a co-located directory; the current runtime-served `dist` is compatible with "one runtime" but not
   with the literal "one binary" claim (RIEKO-AUDIT-009).
2. **Simulation/execution in the v1 workspace.** State explicitly that `rieko-simulation`/
   `rieko-execution` may exist as interface crates but must be unreachable in the v1 binary, and how
   feature-gating is expressed.
3. **Minimum macaroon permissions.** Fix the exact read-only permission set for v1 and forbid
   `admin.macaroon` in defaults/docs.
4. **Definition of "read-only."** Define it operationally: no LND/Core mutation reachable from the
   shipped binary, enforced by CI, not just "no spend call present."
5. **Audit-log durability/immutability.** State the intended guarantee (append-only + tamper-evidence
   level) and that audit entries must equal actual persisted transitions.
6. **LLM privacy boundary.** Define what data may be sent to the provider and require a documented
   redaction/data-minimization toggle.
7. **Status freshness semantics.** Define what `/status` must expose (last ingest, last cycle, source
   status) and that HTTP-up ≠ healthy.
8. **Detector versioning.** Require a detector+detector-version field on findings for stable identity.
9. **Supported networks.** State mainnet/regtest/signet/testnet support expectations and the network
   verification requirement before any live node is used.

---

# 12. Final go/no-go checklist

| Criterion | Verdict |
|---|---|
| Safe for fixture-only development | **PASS** (working slice; duplicates noted) |
| Safe for regtest | **CONDITIONAL** — requires P0 (no-mutation, idempotency, LND auth) |
| Safe for local read-only mainnet observation | **FAIL** — execution reachable (001), LND path broken (003), no idempotency (002) |
| Safe for remote API exposure | **FAIL** — no auth/headers/limits/loopback guard (014) |
| Safe for unattended operation | **FAIL** — alert dedup not persistent (004), unbounded storage (016) |
| Ready for v0.1.0-alpha | **FAIL** — complete P0–P1 and enforce CI gates in §9 |

---

# Threat model (v1) — summary

- **Assets:** LND macaroon, Core credentials, TLS certs, LLM key, Telegram token, node topology/channel
  data, findings/recommendations, audit records, local DB, operator trust.
- **Key adversaries/failures:** remote attacker on an exposed API (014); malicious webpage hitting
  localhost (014, no CORS/CSRF/headers); local unprivileged user running `actions execute` (001/015);
  compromised/hung LLM endpoint (no timeout; but bounded evidence envelope limits prompt-injection
  surface — however peer pubkeys and balances leave the host with no opt-out, see ADR amendment 6);
  prompt injection via evidence strings (contained to explanation output only); stale/honest-but-wrong
  upstream node data (no freshness checks); replay of source data (002); clock skew (timestamps use
  `Utc::now()` in multiple places — `normalize.rs:60`, `common.rs:72` — so replayed old data is stamped
  "now"); disk corruption (no integrity checks); operator misconfiguration (admin macaroon default);
  dependency compromise (clean scan today, no enforcement in CI).
- **Required invariants assessment:** #1–3 not met (001); #4 met (LLM cannot create findings); #5 met
  (NullClient/degrade); #6 not met (002); #7 not met (004); #8 not met (008); #9 met on inspection
  (secrets not logged); #10 not met (014); #11 not met (012 — evidence can be silently dropped on load,
  detector version absent); #12 not met (001 — execution reachable).

---

*Audit performed without modifying code, creating commits/branches/PRs/issues, or touching a real node.
All runtime claims were reproduced against `fixtures/channels.json` with throwaway databases in
`/tmp/rieko-audit/`.*
