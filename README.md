# Rieko

Operational intelligence engine for Bitcoin/Lightning infrastructure.

Rieko is not an AI application. It is an intelligence engine: it observes a node
operator's environment, explains anomalies in plain language, and recommends
actions. AI is one capability inside the engine.

## Quick start

```sh
# Build and scan a fixture (no live node needed)
cargo run -- scan --network regtest --fixture fixtures/channels.json

# Serve the API + embedded UI
cargo run -- serve

# Inspect results
cargo run -- status
```

The scan runs the full v1 pipeline: ingest → detect → recommend → explain →
alert → persist. Findings and recommendations are written to `~/.rieko/rieko.db`
(override with `--db`).

## Step-by-step guide

### 1. Prerequisites

- **Rust** 1.80+ (`rustup` recommended)
- **Node.js** 22+ (for building the frontend; CI builds it for you)
- **LND** 0.17+ (for live-node observation; not needed for fixture scans)

```sh
git clone https://github.com/comwanga/rieko.git
cd rieko
```

### 2. Build

```sh
cd frontend && npm ci && npm run build && cd ..
cargo build --release
```

The release binary embeds the frontend automatically. In development,
`cargo run -- serve` serves the API without the UI; add `--static-dir
frontend/dist` after building the frontend (`cd frontend && npm ci &&
npm run build`).

### 3. Create a read-only macaroon (live LND only)

Do **not** use `admin.macaroon`. Create a restricted macaroon with only the
two permissions Rieko needs:

```sh
lncli bakemacaroon --save_to read-only.macaroon \
  uri:/lnrpc.Lightning/Channels \
  uri:/lnrpc.Lightning/ForwardingHistory
```

An admin macaroon grants far more than Rieko needs and is unnecessary and
unsafe for a read-only watcher.

### 4. First scan — fixture (no node)

```sh
cargo run -- scan --network regtest --fixture fixtures/channels.json
```

This runs the pipeline against a test fixture. Check the results:

```sh
cargo run -- status
```

### 5. First scan — live LND node

```sh
cargo run -- scan \
  --network mainnet \
  --lnd-rest https://localhost:8080 \
  --tls-cert ~/.lnd/tls.cert \
  --macaroon read-only.macaroon \
  --node <your-node-pubkey>
```

Rieko v1 is strictly read-only: it fetches channels and forwarding history,
never mutates state. `--tls-cert` adds LND's `tls.cert` as a trusted root
for that client only; certificate and hostname validation are never
disabled. Without it, a self-signed LND cert is rejected.

### 6. Continuous monitoring

Track channel liquidity over time (records one snapshot per channel per cycle,
feeding both the liquidity detector and the drift trend detector):

```sh
# Against a fixture (development)
cargo run -- monitor --network regtest --fixture fixtures/channels.json --interval 300

# Against a live node
cargo run -- monitor \
  --network mainnet \
  --lnd-rest https://localhost:8080 \
  --tls-cert ~/.lnd/tls.cert \
  --macaroon read-only.macaroon \
  --node <your-node-pubkey> \
  --interval 300
```

The monitor persists findings, recommendations, and channel snapshots each
cycle. Snapshot history is bounded by a configurable retention policy
(`--retention-days` default 30, `--closed-retention-days` default 3,
`--max-snapshots-per-channel`, `--cleanup-interval` default 6 hours).
Transient LND ingestion failures are retried three times with bounded backoff.
If a retry round is exhausted, status records the disconnection and monitoring
continues after the configured interval instead of exiting.

### 7. Inspect status

```sh
cargo run -- status
```

Reports overall health (Healthy/Degraded/Unhealthy/NotInitialized), schema
version, uptime, source connectivity, table counts, last ingestion/cycle
timestamps, LLM/alert config, cleanup state, and database integrity.

### 8. Serve the API and UI

```sh
# Loopback only (safe default)
cargo run -- serve --db ~/.rieko/rieko.db

# Non-loopback (requires --allow-external + bearer token)
cargo run -- serve --addr 0.0.0.0:8080 --allow-external \
  --token-file /run/secrets/rieko-token
```

The release binary embeds the UI at `/`. API endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /` | Embedded UI |
| `GET /status` | Operational status |
| `GET /findings?limit=N&lifecycle=active` | Recent findings; lifecycle is `active` (default), `resolved`, or `all` |
| `GET /findings/channel/:id?lifecycle=active` | Findings for a channel, with the same lifecycle filter |
| `GET /recommendations?limit=N` | Recent recommendations |
| `GET /audit?limit=N` | Audit trail |
| `GET /snapshots?limit=N` | Channel snapshots |
| `GET /snapshots/channel/:id` | Snapshots for a channel |
| `POST /api/v2/simulations` | Create and persist a local deterministic projection |
| `GET /api/v2/simulations?limit=N` | Recent replayable projections |
| `GET /api/v2/simulations/:id` | Projection detail |
| `GET /api/v2/simulations/:id/report` | Projection detail in the current report-compatible shape |
| `POST /api/v2/simulations/compare` | Compare compatible local projections |

Simulation POST routes write only local projection records; they never contact
or mutate a node. All other routes are read-only. Security headers (CSP,
X-Content-Type-Options, frame/referrer/cross-origin protection) are applied to
every response. Request size is capped at 1 MB; queries are bounded (1–500
limit, default 50).

### 9. Optional: LLM explanations

OpenAI-compatible API (works with Ollama):

```sh
export RIEKO_LLM_ENDPOINT=https://api.openai.com/v1/chat/completions
export RIEKO_LLM_API_KEY=sk-...
export RIEKO_LLM_MODEL=gpt-4o-mini
```

The LLM summarises structured evidence into plain-language explanations.
Detectors never depend on the LLM; Rieko remains functional when it is
unavailable. LLM HTTP calls use finite deadlines: 5 seconds to connect and 30
seconds for the complete request. At most three findings are sent for
explanation per cycle, keeping the optional integration from starving the
authoritative monitor pipeline.

### 10. Optional: Telegram alerts

Alerts are deduplicated with a persistent cooldown (survives restart):

```sh
export RIEKO_TELEGRAM_TOKEN=...
export RIEKO_TELEGRAM_CHAT_ID=...
```

Severity escalation (e.g. Warning → Critical) pierces the cooldown and
delivers immediately. Failed deliveries do not consume the cooldown.

### 11. Simulation (v2, default-enabled)

`rieko simulations create` projects a hypothetical liquidity transfer
and records the deterministic result using the `liquidity-redistribution`
model — it does not move real funds:

```sh
cargo run -- simulations create \
  --recommendation <rec-id> \
  --model liquidity-redistribution \
  --source-channel <id> --destination-channel <id> --amount-sats 50000

cargo run -- simulations list
cargo run -- simulations show <sim-id>
```

Simulation is node-read-only and deterministic. It requires source and destination
snapshots from the same observation, embeds those exact inputs for replay, and
rejects data older than 15 minutes unless the operator explicitly uses
`--force`; forced stale results remain marked stale. See
[docs/adrs/0005-v2-deterministic-simulation.md](docs/adrs/0005-v2-deterministic-simulation.md).
Databases upgraded to schema v11 need one new monitor cycle with an explicit
`--network` before simulation, because legacy snapshots do not contain a
trustworthy network, local-node identity, or state digest.

### 12. Execution (v3, interlocked)

The draft execution code remains compile-time isolated behind `--features
execute`, but live execution is intentionally refused even in that build.
Simulation integrity is only the first prerequisite; durable execution
idempotency, verified LND protocol behavior, confirmation, pre-flight checks,
and regtest fault testing are not complete.

```sh
cargo run --features execute -- actions list
cargo run --features execute -- actions approve <id> --actor alice
```

Do not use Rieko for node mutation. The draft threat model is documented in
[docs/adrs/0003-human-in-the-loop-threat-model.md](docs/adrs/0003-human-in-the-loop-threat-model.md)
and [docs/adrs/0004-mainnet-readiness-approval-workflow.md](docs/adrs/0004-mainnet-readiness-approval-workflow.md).

## Architecture

See [docs/adrs/0001-rieko-v1-architecture.md](docs/adrs/0001-rieko-v1-architecture.md).

```
LND / Core ──▶ Normalizers ──▶ Domain Objects ──▶ Graph ──▶ Detectors ──▶ Recommendations
                                                    │
                                              Explanations (LLM)
                                                    │
                                              Alerts (Telegram)
```

The pipeline is protocol-agnostic: detectors consume domain objects, not raw
LND protobufs. Adding a new node source (CLN, LDK, Eclair) means writing a
new normalizer — detectors and recommendations stay unchanged.

### Detectors

| Detector | ID | What it detects |
|----------|----|----------------|
| **Liquidity** | `channel_liquidity` | Channels imbalanced below threshold (outbound/inbound/severely drained) |
| **Drift** | `liquidity_trend` | Channels trending toward drain over multiple snapshots, even before crossing the hard threshold |

Both detectors produce deterministic findings with stable identities; replay
creates zero duplicates.

## Crates

| Crate | Layer | Description |
|-------|-------|-------------|
| `rieko-domain` | Kernel | Domain model — depends on nothing |
| `rieko-graph` | Kernel | In-memory typed graph with adjacency index and path-finding |
| `rieko-storage` | Persistence | SQLite + in-memory storage behind a trait |
| `rieko-findings` | Engine | Typed findings, actions, audit log, identity |
| `rieko-ingest-lnd` | Ingest | LND REST client and normalizer |
| `rieko-ingest-core` | Ingest | Bitcoin Core normalizer |
| `rieko-detectors` | Engine | Liquidity and drift detectors |
| `rieko-recommendations` | Engine | Findings → recommendations |
| `rieko-alerts` | Engine | Alert dedup, cooldown, Telegram sink |
| `rieko-llm` | Engine | LLM explanation client |
| `rieko-status` | Engine | Health assessment and status model |
| `rieko-simulation` | Kernel | Pure deterministic what-if models (v2) |
| `rieko-simulation-app` | Application | Simulation validation, persistence, and public views |
| `rieko-execution` | Future | LND-backed executor with approval gate (v3) |
| `rieko-api` | Interface | axum HTTP API, serves embedded UI |
| `rieko-cli` | Interface | CLI entrypoint |

## Database upgrades

The SQLite database is versioned internally (`PRAGMA user_version`) and
migrated automatically and transactionally when a newer binary opens it.
`rieko status` reports the schema version applied to your database.

- A database created by an older version is upgraded in place on first open.
- Data is preserved across upgrades; each step runs inside a transaction, so a
  failed step rolls back cleanly.
- A database from a **newer** version than this binary understands is
  rejected rather than risked.

Back up before upgrading:

```sh
sqlite3 ~/.rieko/rieko.db ".backup '~/.rieko/backup.db'"
```

## Operational model

Rieko runs one authoritative **monitor writer** at a time. The API can also
persist local simulation projections, but it cannot execute actions or mutate a
node. SQLite WAL permits concurrent readers and serializes these short writes.

- The database is opened in WAL mode with `synchronous=NORMAL`, foreign
  keys enforced, and a finite busy timeout.
- A second monitor is **rejected up front** via a writer lock.
- Each detector cycle (findings, recommendations, explanations, audit
  transitions) is committed as **one atomic transaction**.
- The audit log is **append-only through the application**: every state
  transition is written with its audit entry in one transaction; the
  database rejects normal `UPDATE`/`DELETE` on audit rows via triggers.
- Status queries are O(1) — no full table scans.

## First-time mainnet validation

Before connecting to mainnet, run through this checklist (see also
`regtest/README.md` for the regtest harness):

1. [ ] Create a restricted read-only macaroon (step 3 above).
2. [ ] Run one `scan` cycle with no LLM, no Telegram.
3. [ ] Verify findings against `lncli listchannels` and `lncli fwdinghistory`.
4. [ ] Replay the scan — findings, recommendations, and audit entries must be
       unchanged (zero duplicates).
5. [ ] Start `monitor` with `--interval 300`. Let it run at least one full cycle.
6. [ ] Check `cargo run -- status` for Healthy overall status.
7. [ ] Enable Telegram only after core observation is verified.
8. [ ] Enable LLM only after confirming the data-sharing implications.

## License

Apache-2.0
