# Changelog

All notable changes to Rieko are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Rieko uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Stale marker on findings**: every finding returned by the API carries
  `observation_stale`, true when an active finding has not been re-confirmed
  for two hours or twice the agent's longest polling interval, whichever is
  longer. It is computed when read and nothing stored changes. The UI shows a
  "Stale" tag; `rieko findings`, `explain`, `watch` and `doctor` show the flag.
  Findings from a one-shot `rieko scan` read as stale once that threshold has
  passed, since nothing re-confirms them.
- **Source poll-failure findings** (`rieko-agent`): `bitcoin_core_poll_failure`
  and `lnd_poll_failure` are raised when three consecutive polls of that source
  fail, and resolve after three successful polls. The threshold is a heuristic
  and is recorded in the finding's evidence.
- **GetInfo-based identity discovery** (`rieko-ingest-lnd`): `LndClient::get_info()`
  now derives node identity from `/v1/getinfo` rather than relying on a
  caller-supplied `--node` flag. The CLI flag is now optional and emits a warning
  on mismatch.
- **HTTPS enforcement**: Plain `http://` LND REST endpoints are now rejected by
  default to prevent credential leakage. Pass `--allow-insecure` for local
  regtest/signet nodes only.
- **Snapshot persistence in `scan`**: One-shot `rieko scan` runs now persist
  channel liquidity snapshots to the database alongside findings, so the
  `/snapshots` API reflects data for single-scan users.
- **Fixture alerting suppression**: `monitor` and `scan` commands with a
  `--fixture` source no longer fire Telegram alerts, preventing fixture runs from
  consuming live deduplication cooldowns. Live alerts use a `live|telegram` sink
  namespace to maintain separation.
- **Recommendation lifecycle (V14 migration)**: Recommendations now carry a
  `lifecycle` column (`active` | `resolved`). Resolved findings cascade their
  lifecycle to linked recommendations via `sync_recommendation_lifecycles()`,
  called atomically inside each persist cycle.
- **`/recommendations` active-only filter**: The API now returns only active
  recommendations by default; resolved ones remain visible in the audit trail.
- **Synthetic-data annotation**: `seed_demo.rs` test fixture data is now
  explicitly annotated as non-operational to prevent accidental use as evidence.
- **GitHub Actions CI**: `.github/workflows/ci.yml` adds audit, test, clippy,
  format-check, and release jobs. `.github/workflows/regtest.yml` adds a nightly
  fixture-based smoke test.

### Changed
- **`/status` health covers Bitcoin Core and LND polling**: a polled source that
  is disconnected makes the overall state `degraded`, or `unhealthy` if it has
  never connected. An agent polling only Core or LND now leaves
  `not_initialized` after its first successful poll. `/inspect/bitcoin` and
  `/inspect/lightning` include a `consecutive_failures` count.
- `--node` flag in `scan` and `monitor` is now advisory; the live LND node
  identity takes precedence.
- `GraphSource` gained `allow_insecure: bool` propagated from both `scan` and
  `monitor` argument structs.

### Fixed
- `settlement_reliability` detector no longer silently returns no findings when
  BTCPay webhook events are absent; a `debug`-level message explains the cause.
- `rieko-detectors` no longer imports `tracing` (not a declared dependency);
  replaced with a comment.

### Security
- LND REST transport now enforces TLS by default (`InsecureTransport` error on
  plain `http://`). Use `--allow-insecure` only for local test networks.
