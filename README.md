# Rieko

Operational intelligence engine for Bitcoin/Lightning infrastructure.

Rieko is not an AI application. It is an intelligence engine: it observes a node
operator's environment, explains anomalies in plain language, and recommends
actions. AI is one capability inside the engine.

## Quick start

```sh
# Build and scan a fixture (no live node needed)
cargo run -- scan --fixture fixtures/channels.json

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
cargo run -- scan --fixture fixtures/channels.json
```

This runs the pipeline against a test fixture. Check the results:

```sh
cargo run -- status
```

### 5. First scan — live LND node

```sh
cargo run -- scan \
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
cargo run -- monitor --fixture fixtures/channels.json --interval 300

# Against a live node
cargo run -- monitor \
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
| `GET /findings?limit=N` | Recent findings |
| `GET /findings/channel/:id` | Findings for a channel |
| `GET /recommendations?limit=N` | Recent recommendations |
| `GET /audit?limit=N` | Audit trail |
| `GET /snapshots?limit=N` | Channel snapshots |
| `GET /snapshots/channel/:id` | Snapshots for a channel |

All routes are read-only (`GET`). Security headers (CSP, X-Content-Type-Options,
frame/referrer/cross-origin protection) are applied to every response. Request
size is capped at 1 MB; queries are bounded (1–500 limit, default 50).

### 9. Optional: LLM explanations

OpenAI-compatible API (works with Ollama):

```sh
export RIEKO_LLM_ENDPOINT=https://api.openai.com/v1/chat/completions
export RIEKO_LLM_API_KEY=sk-...
export RIEKO_LLM_MODEL=gpt-4o-mini
```

The LLM summarises structured evidence into plain-language explanations.
Detectors never depend on the LLM; Rieko remains functional when it is
unavailable.

### 10. Optional: Telegram alerts

Alerts are deduplicated with a persistent cooldown (survives restart):

```sh
export RIEKO_TELEGRAM_TOKEN=...
export RIEKO_TELEGRAM_CHAT_ID=...
```

Severity escalation (e.g. Warning → Critical) pierces the cooldown and
delivers immediately. Failed deliveries do not consume the cooldown.

### 11. Future features (--features future)

Simulation and execution are post-v1 capabilities gated behind the `future`
Cargo feature. They are not available in the default build:

```sh
cargo run --features future -- simulate --fixture fixtures/channels.json
cargo run --features future -- actions list
cargo run --features future -- actions approve <id> --actor alice
cargo run --features future -- actions execute <id> --actor alice \
  --lnd-rest https://localhost:8080 --tls-cert ~/.lnd/tls.cert \
  --macaroon read-only.macaroon --allow-mainnet
```

See [docs/adrs/0002-rebalance-execution-safety.md](docs/adrs/0002-rebalance-execution-safety.md)
and the following ADRs for the execution threat model.

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
| `rieko-simulation` | Future | What-if projection of actions (v2) |
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

Rieko runs one **writer** at a time (the `monitor`) and any number of
readers (the API). This matches SQLite WAL: many concurrent readers with a
single writer.

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
