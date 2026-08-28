# Rieko

Operational intelligence engine for Bitcoin/Lightning infrastructure.

Rieko observes a node operator's environment, detects and explains anomalies,
recommends safe actions, and lets operators simulate hypothetical outcomes —
all without ever mutating node state in the default build.

## Quick start (no LND needed)

```sh
# Build and serve with embedded UI
cd frontend && npm ci && npm run build && cd ..
cargo run --release -- serve

# In another terminal, query the running API
cargo run -- status

# Or stop the agent, scan a fixture, then start it again to expose the result
cargo run -- scan --network regtest --fixture fixtures/channels.json
cargo run -- serve
# In another terminal:
cargo run -- status
```

Open `http://localhost:8080` for the UI. The scan runs the pipeline: ingest →
detect → recommend → explain → alert → persist. Findings are written to
`~/.rieko/rieko.db` by default (override with `--db`).

## Running locally

### Prerequisites

- **Rust** 1.86+
- **Node.js** 22+ (for building the frontend)
- **LND** 0.17+ (optional — only for live-node observation)

### Build

```sh
git clone https://github.com/comwanga/rieko.git
cd rieko
cd frontend && npm ci && npm run build && cd ..
cargo build --release
```

The release binary embeds the frontend. In development, `cargo run -- serve`
serves the API without the UI; add `--static-dir frontend/dist` after building
the frontend.

### Fixture scan (no LND)

```sh
cargo run -- scan --network regtest --fixture fixtures/channels.json
cargo run -- serve
# In another terminal:
cargo run -- status
```

### Live LND scan

```sh
cargo run -- scan \
  --network mainnet \
  --lnd-rest https://localhost:8080 \
  --tls-cert ~/.lnd/tls.cert \
  --macaroon read-only.macaroon \
  --node <your-node-pubkey>
```

Create a restricted read-only macaroon:

```sh
lncli bakemacaroon --save_to read-only.macaroon \
  uri:/lnrpc.Lightning/Channels \
  uri:/lnrpc.Lightning/ForwardingHistory
```

### Continuous monitoring

```sh
cargo run -- monitor \
  --network mainnet \
  --lnd-rest https://localhost:8080 \
  --tls-cert ~/.lnd/tls.cert \
  --macaroon read-only.macaroon \
  --node <your-node-pubkey> \
  --interval 300
```

Snapshot retention is configurable with `--retention-days` (default 30),
`--closed-retention-days` (default 3), and `--cleanup-interval` (default 6h).

### Serve API and UI

```sh
# Loopback (safe default)
cargo run -- serve

# Non-loopback (requires token)
cargo run -- serve --addr 0.0.0.0:8080 --allow-external \
  --token-file /run/secrets/rieko-token

# Run the long-lived agent with authenticated BTCPay webhook ingestion
cargo run --bin rieko-agent -- \
  --btcpay-webhook-secret-file /run/secrets/btcpay-webhook-secret \
  --btcpay-network mainnet \
  --btcpay-node <your-node-pubkey>

# `rieko serve` remains a compatibility alias for the same agent runtime
cargo run --bin rieko -- serve \
  --btcpay-webhook-secret-file /run/secrets/btcpay-webhook-secret \
  --btcpay-network mainnet \
  --btcpay-node <your-node-pubkey>

# Read active findings from the running local agent as typed JSON
cargo run --bin rieko -- findings

# Read operational status from the same authenticated local API
cargo run --bin rieko -- status

# Include resolved findings when the API requires authentication
cargo run --bin rieko -- findings --lifecycle all \
  --token-file /run/secrets/rieko-token

# Stream current findings, then only new findings or lifecycle transitions
cargo run --bin rieko -- watch --interval 5

# Return one exact persisted finding, including explanation and evidence
cargo run --bin rieko -- explain <finding-id>

# Inspect exact persisted operational state (add --json for typed JSON)
cargo run --bin rieko -- inspect btcpay
cargo run --bin rieko -- inspect bitcoin
cargo run --bin rieko -- inspect lightning
cargo run --bin rieko -- inspect all

# Summarize status, persisted source state, and active findings
cargo run --bin rieko -- doctor
```

Save a non-secret BTCPay connection configuration without contacting BTCPay,
then start the agent with it:

```sh
rieko attach btcpay \
  --config /etc/rieko/rieko.json \
  --greenfield-url https://btcpay.example.com \
  --store <store-id> \
  --api-key-file /run/secrets/btcpay-greenfield.key \
  --network mainnet

rieko-agent --config /etc/rieko/rieko.json
```

The configuration stores only the API-key file reference, never the key value.

For a dedicated non-root Linux service with explicit configuration, database,
and secret-file permissions, see [the systemd deployment example](docs/deploy-systemd.md).
For a container sidecar using the same configuration and secret-file semantics,
see [the Docker Compose deployment example](docs/deploy-docker-compose.md).

Tagged releases publish the non-root agent image as
`ghcr.io/comwanga/rieko:<version>`. The current stable image is
`ghcr.io/comwanga/rieko:v0.1.1`. For example:

```sh
docker pull ghcr.io/comwanga/rieko:v0.1.1
docker run --rm --name rieko-agent \
  -p 127.0.0.1:8080:8080 \
  -v /etc/rieko:/etc/rieko:ro \
  -v /run/secrets:/run/secrets:ro \
  -v /var/lib/rieko:/var/lib/rieko \
  ghcr.io/comwanga/rieko:v0.1.1 \
  --config /etc/rieko/rieko.json \
  --db /var/lib/rieko/rieko.db \
  --token-file /run/secrets/rieko-api-token \
  --addr 0.0.0.0:8080 --allow-external
```

The mounted files and database directory must be readable or writable as
appropriate by container UID/GID `10001:10001`.

Each tagged image also has keyless GitHub build-provenance and SPDX 2.3 JSON
SBOM attestations bound to its immutable image digest. After authenticating to
GHCR, verify the provenance and the registry-hosted SBOM attestation with:

```sh
docker login ghcr.io
gh attestation verify oci://ghcr.io/comwanga/rieko:v0.1.1 \
  --repo comwanga/rieko --bundle-from-oci
gh attestation verify oci://ghcr.io/comwanga/rieko:v0.1.1 \
  --repo comwanga/rieko --bundle-from-oci \
  --predicate-type https://spdx.dev/Document/v2.3
```

The signing identity comes from GitHub Actions OIDC; no repository signing key
is required.

The matching Linux x86_64 `rieko` operator CLI and its SHA-256 checksum are
published on the same GitHub Release. See the
[Docker Compose deployment guide](docs/deploy-docker-compose.md#install-the-operator-cli)
for checksum verification and installation without a Rust toolchain.

## API endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Embedded UI |
| `GET /status` | Health, counts, simulation breakdown |
| `GET /inspect/btcpay` | Exact persisted BTCPay operational state |
| `GET /inspect/bitcoin` | Exact persisted Bitcoin Core operational state |
| `GET /inspect/lightning` | Exact persisted Lightning operational state |
| `GET /findings?limit=N&lifecycle=active` | Findings (active, resolved, or all) |
| `GET /findings/:id` | One exact persisted finding |
| `GET /findings/channel/:id` | Findings for a channel |
| `GET /recommendations?limit=N` | Recommendations |
| `GET /audit?limit=N` | Audit trail |
| `GET /snapshots?limit=N` | Channel snapshots |
| `GET /snapshots/channel/:id` | Snapshots for a channel |
| `GET /snapshots/channel/:id?network=N&node_id=N` | Network-filtered snapshots |
| `POST /api/v1/integrations/btcpay/webhook` | BTCPay Server Greenfield webhook receiver (HMAC-SHA256) |
| `POST /api/v2/simulations` | Create local deterministic projection |
| `GET /api/v2/simulations?limit=N` | Recent replayable projections |
| `GET /api/v2/simulations/:id` | Projection detail |
| `GET /api/v2/simulations/:id/report` | Structured simulation report |
| `POST /api/v2/simulations/compare` | Compare two projections |

Simulation POST routes produce local projections only — they never contact or
mutate a node. All other routes are read-only. Request size is capped at 1 MB
and pagination is bounded 1–500 (default 50). Simulation creation is rate-limited
to 5 requests per second.

## BTCPay Server Greenfield Integration

Rieko supports ingestion from BTCPay Server Greenfield:
- **Webhook Ingestion**: Real-time event streaming (`InvoiceSettled`, `InvoiceExpired`, `InvoicePaymentReceived`) via `POST /api/v1/integrations/btcpay/webhook` with constant-time HMAC-SHA256 signature verification (`BTCPay-Sig`).
- **Finding Pipeline**: `rieko-agent` owns the long-running webhook, detector, persistence, and local API runtime. `rieko serve` delegates to that same implementation for compatibility. When configured with the webhook secret, network, and node scope, normalized invoice events feed the deterministic settlement-reliability detector and findings are persisted for `GET /findings` and the API-backed `rieko findings` command. The endpoint fails closed when this integration is not configured.
- **REST Client**: Asynchronous polling of Lightning info, channels, balances, on-chain wallets, and invoices.
- **Normalized Ingestion Adapter**: Pluggable `NodeIngestionAdapter` yielding an asynchronous stream of normalized domain `NodeEvent` and `NodeSnapshot` objects.

## Simulation (v2, enabled by default)

Rieko v2 can project hypothetical liquidity transfers using the deterministic
`liquidity-redistribution` model:

```sh
cargo run -- simulations create \
  --recommendation <rec-id> \
  --model liquidity-redistribution \
  --source-channel <id> --destination-channel <id> --amount-sats 50000

cargo run -- simulations list
cargo run -- simulations show <sim-id>
```

Every simulation:
- Is bound to the exact source/destination snapshots observed at the time
- Produces the same result for the same input (deterministic, SHA-256 identity)
- Shows baseline, projection, deltas, assumptions, warnings, and confidence
- Includes a safety statement confirming no action was executed
- Is rate-limited (5/sec) to prevent resource exhaustion
- Persists its canonical input so results survive snapshot retention

See `docs/adrs/0005-v2-deterministic-simulation.md` for the full contract.

## LLM explanations (optional)

```sh
export RIEKO_LLM_ENDPOINT=https://api.openai.com/v1/chat/completions
export RIEKO_LLM_API_KEY=sk-...
export RIEKO_LLM_MODEL=gpt-4o-mini
```

LLMs provide plain-language summaries of detector evidence. The engine remains
fully functional without an LLM — detection and recommendations are always
deterministic. A template-based simulation explanation is generated
deterministically; LLM output is not required for simulation.

## Telegram alerts (optional)

```sh
export RIEKO_TELEGRAM_TOKEN=...
export RIEKO_TELEGRAM_CHAT_ID=...
```

Alerts are deduplicated with a persistent cooldown that survives restarts.
Failed deliveries do not consume the cooldown. Severity escalation (Warning
→ Critical) pierces the cooldown immediately.

## Architecture

```
LND / BTCPay / Core ──▶ Ingestion Adapters ──▶ Normalized Domain Events / Snapshots ──▶ Graph ──▶ Detectors ──▶ Recommendations
                                                                                                      │               │
                                                                                                Explanations      Simulations
                                                                                                      │          (deterministic)
                                                                                                 Alerts
```

### Detectors

| Detector | ID | What it detects |
|----------|----|----------------|
| Liquidity | `channel_liquidity` | Channels imbalanced below threshold (outbound/inbound/severely drained) |
| Drift | `liquidity_trend` | Channels trending toward drain over multiple snapshots |
| Settlement reliability | `settlement_reliability` | Repeated BTCPay invoice settlement failures in the bounded event window |
| BTCPay backend health | `btcpay_backend_health` | Persisted Greenfield connectivity is degraded |
| Bitcoin Core sync correlation | `bitcoin_core_sync_correlation` | BTCPay and Core are reachable, but persisted Core state is unsynchronized |
| Lightning chain sync correlation | `lightning_chain_sync_correlation` | BTCPay and synchronized Core are reachable, but persisted LND state is not synced to chain |

They produce deterministic findings with stable identities. Replay produces
zero duplicates.

### Crates

| Crate | Layer | Description |
|-------|-------|-------------|
| `rieko-domain` | Kernel | Domain models (`NodeEvent`, `NodeSnapshot`, `NodeIngestionAdapter`) |
| `rieko-graph` | Kernel | Typed graph with path-finding |
| `rieko-storage` | Persistence | SQLite + in-memory storage |
| `rieko-findings` | Engine | Typed findings, actions, identity, observation sources |
| `rieko-ingest-btcpay` | Ingest | BTCPay Server Greenfield client, webhook verifier, and adapter |
| `rieko-ingest-lnd` | Ingest | LND REST client and normalizer |
| `rieko-ingest-core` | Ingest | Bitcoin Core normalizer |
| `rieko-detectors` | Engine | Deterministic liquidity, settlement, backend-health, and cross-source correlation detectors |
| `rieko-recommendations` | Engine | Findings → recommendations |
| `rieko-alerts` | Engine | Alert dedup, cooldown, Telegram |
| `rieko-llm` | Engine | LLM explanation client |
| `rieko-status` | Engine | Health assessment |
| `rieko-simulation` | Kernel | Pure deterministic what-if model |
| `rieko-simulation-app` | Application | Simulation orchestration and views |
| `rieko-execution` | Future | LND mutator behind `--features execute` |
| `rieko-api` | Interface | axum HTTP API + embedded UI |
| `rieko-cli` | Interface/runtime | `rieko` operator CLI, `rieko-agent` daemon, and their shared agent runtime |

## Database

The SQLite database is versioned internally and migrated transactionally on open.
With `rieko-agent` or `rieko serve` running, use `cargo run -- status` to see
the schema version through the local API. Back up before upgrading:

```sh
sqlite3 ~/.rieko/rieko.db ".backup 'backup.db'"
```

### Operational model

- One authoritative monitor writer at a time; concurrent readers via WAL
- WAL mode with `synchronous=NORMAL`, foreign keys enforced, finite busy timeout
- Second monitor rejected up front via writer lock
- Normalized BTCPay webhook events are committed before acknowledgement and replayed after agent restart until their detector cycle commits
- Each detector cycle committed in one atomic transaction
- Audit log is append-only via trigger-level enforcement
- Status queries are O(1) — no full table scans
- Simulation results are appended and never retroactively modified; canonical
  input is embedded in every record so results survive snapshot retention

## Execution (feature-gated)

The `--features execute` build exposes draft action workflow commands, but live
execution is interlocked at runtime and not supported for production use.

```sh
cargo run --features execute -- actions list
```

Do not use Rieko for node mutation. See `docs/adrs/0003-human-in-the-loop-threat-model.md`
and `docs/adrs/0002-rebalance-execution-safety.md`.

## CI and testing

```sh
cargo test --workspace --all-features
cargo test -p rieko-cli --test release_e2e     # E2E binary smoke test
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

The CI verifies that the default `--features simulate` binary contains no
execution dependency via `cargo tree`.

## License

Apache-2.0
