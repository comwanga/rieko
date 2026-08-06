# Rieko

Operational intelligence engine for Bitcoin/Lightning infrastructure.

Rieko is not an AI application. It is an intelligence engine: it observes a node
operator's environment, explains anomalies in plain language, and recommends
actions. AI is one capability inside the engine.

## Architecture

See [docs/adrs/0001-rieko-v1-architecture.md](docs/adrs/0001-rieko-v1-architecture.md).

```
LND / Core ──▶ Normalizers ──▶ Domain Objects ──▶ Graph ──▶ Detectors
```

## Crates

- `rieko-domain` — domain model (kernel, no dependencies)
- `rieko-graph` — typed graph (kernel, depends on `rieko-domain`)
- `rieko-storage` — SQLite persistence behind a trait
- `rieko-findings` — typed findings and actions + audit log
- `rieko-ingest-lnd` — LND normalizer
- `rieko-ingest-core` — Bitcoin Core normalizer
- `rieko-detectors` — domain → findings
- `rieko-recommendations` — findings → recommendations
- `rieko-alerts` — alerting with dedup/cooldown
- `rieko-llm` — LLM explanation client
- `rieko-api` — axum API + static frontend
- `rieko-cli` — CLI entrypoint

## Quick start

```sh
cargo run -- scan --fixture fixtures/channels.json
```

The scan runs the full v1 slice: ingest → detect → recommend → explain →
alert → persist. Findings and recommendations are written to `~/.rieko/rieko.db`
(override with `--db`).

Against a live node (Rieko v1 is strictly read-only — it only fetches
channels and forwarding history, never mutates state):

```sh
cargo run -- scan --lnd-rest https://localhost:8080 \
  --tls-cert ~/.lnd/tls.cert --macaroon read-only.macaroon \
  --node <your-node-pubkey>
```

`--tls-cert` adds LND's `tls.cert` as a trusted root for that client only;
certificate and hostname validation are never disabled. Without it, a
self-signed LND cert is rejected.

For the macaroon, do **not** use `admin.macaroon`. Create a restricted
macaroon containing only the two permissions Rieko v1 exercises:

- `Lightning.Channels` — reads `GET /v1/channels`
- `Lightning.ForwardingHistory` — reads `GET /v1/forwarding/events`

For example with `lncli`:

```sh
lncli bakemacaroon --save_to read-only.macaroon \
  uri:/lnrpc.Lightning/Channels uri:/lnrpc.Lightning/ForwardingHistory
```

An admin macaroon grants far more than Rieko needs and is unnecessary and
unsafe for a read-only watcher.

Optional LLM explanations (OpenAI-compatible; works with Ollama too):

```sh
export RIEKO_LLM_ENDPOINT=https://api.openai.com/v1/chat/completions
export RIEKO_LLM_API_KEY=sk-...
export RIEKO_LLM_MODEL=gpt-4o-mini
```

Telegram alerts (deduped with a 1h cooldown per finding):

```sh
export RIEKO_TELEGRAM_TOKEN=...
export RIEKO_TELEGRAM_CHAT_ID=...
```

Track channel liquidity history over time (records one `channel_snapshots`
row per channel per cycle, feeding the drift detector and the Channels UI):

```sh
cargo run -- monitor --fixture fixtures/channels.json --interval 300
# or against a live node: --lnd-rest https://localhost:8080 --tls-cert ~/.lnd/tls.cert --macaroon read-only.macaroon
```

The LND client targets the 0.17+ REST schema: 64-bit fields are read as
strings, and `chan_status_flags` is parsed as LND's ChannelStatus string
(`ChanStatusDefault` is open; `ChanStatusBorked`/`ChanStatus*Close*` map to a
closing state; any unrecognised or malformed combination maps to `Unknown`,
never `Active`). Forwarding-event channel ids are resolved to channel points
where a channel is known; unresolvable ids are preserved verbatim (`scid:…`)
and not correlated. Event timestamps come from the source (`timestamp_ns` when
present), never from processing time.

Snapshot history is bounded: the monitor prunes stale rows on a schedule so
the database cannot grow without limit. Tune it with `--retention-days`
(default 30; older active-channel history is deleted), `--closed-retention-days`
(default 3; closed channels are kept for a shorter grace period),
`--max-snapshots-per-channel N`, and `--cleanup-interval HOURS` (default 6).
Each cleanup runs in a transaction, never touches findings or
recommendations, and its success/failure is surfaced in `rieko status`.

Inspect stored state and serve the read-only API, plus the built UI:

```sh
cargo run -- status --db ~/.rieko/rieko.db
cargo run -- serve --db ~/.rieko/rieko.db --addr 127.0.0.1:8080 \
  --static-dir frontend/dist
# UI at http://127.0.0.1:8080/  (build it first with `npm run build` in frontend/)
# GET /status, /findings, /findings/channel/{id}, /recommendations,
#     /audit, /snapshots, /snapshots/channel/{id}
```

By default the API binds loopback only. Binding a non-loopback address is
refused unless you pass `--allow-external` *and* provide a bearer token
(`--token-file FILE` or the `RIEKO_API_TOKEN` env var); the API then requires
`Authorization: Bearer <token>` on every JSON route. The API serves only GET
(read-only) routes and honours request-size, timeout, and security headers
(CSP, `X-Content-Type-Options`, frame/referrer protection) on all responses.

```sh
cargo run -- serve --addr 0.0.0.0:8080 --allow-external --token-file /run/secrets/rieko-token
```

## Database upgrades

The SQLite database is versioned internally (`PRAGMA user_version`) and
migrated automatically and transactionally when a newer binary opens it.
`rieko status` reports the schema version applied to your database.

* A database created by an older version is upgraded in place on first open.
* Data is preserved across these upgrades; each step runs inside a
  transaction, so a failed step rolls back cleanly.
* A database from a **newer** version than this binary understands is
  rejected rather than risked.

As with any SQLite database, take a backup before upgrading a long-lived node:

```sh
sqlite3 ~/.rieko/rieko.db ".backup '~/.rieko/backup.db'"
```

## Operational model

Rieko runs one **writer** at a time (the `monitor`) and any number of
readers (the API). This matches SQLite WAL: many concurrent readers with a
single writer.

* The database is opened in WAL mode with `synchronous=NORMAL` (durable
  enough for the OS-crash case Rieko targets), foreign keys enforced, and a
  finite busy timeout so a transient write conflict is retried rather than
  failing instantly.
* A second monitor is **rejected up front** via a writer lock, so two
  processes cannot silently corrupt a database. Only one writer process is
  supported; the API never writes.
* Each detector cycle (findings, explanations, recommendations and audit
  transitions) is committed as **one atomic transaction**. A failure
  mid-cycle rolls back cleanly, never leaving half-written state.
* The audit log is **append-only through the application**: every state
  transition is written together with its audit entry in one transaction, and
  the database rejects normal `UPDATE`/`DELETE` on audit rows via triggers.
  This is a guarantee of *application and database-level* append-onlyness, not
  cryptographic immutability: a local administrator with raw filesystem access
  to the database file can still alter it. Cryptographic tamper evidence is
  not implemented.
* `rieko status` runs a database integrity check and refuses to report the
  database as healthy when that check fails.

## First-time mainnet validation

Mainnet observation must not be enabled until every step in this checklist
passes (Phase 6.2 / controlled local observation validation).

### Prerequisites

- [ ] All CI gates are green (`cargo test --workspace --all-features`).
- [ ] Regtest integration tests pass (see `regtest/README.md`).
- [ ] The release binary is built and verified (Release workflow completes).

### Validation procedure

1. **Create a restricted read-only macaroon**
   ```sh
   lncli bakemacaroon --save_to read-only.macaroon \
     uri:/lnrpc.Lightning/Channels uri:/lnrpc.Lightning/ForwardingHistory
   ```
   Do **not** use `admin.macaroon`. The macaroon must grant exactly the two
   permissions above.

2. **Start with a fresh, backed-up database**
   ```sh
   cp ~/.rieko/rieko.db ~/.rieko/backup.db   # if one exists
   rm ~/.rieko/rieko.db                       # start clean
   ```

3. **Run ONE observation cycle with no extras**
   ```sh
   # No LLM, no Telegram, loopback only.
   ./rieko scan \
     --lnd-rest https://localhost:8080 \
     --tls-cert ~/.lnd/tls.cert \
     --macaroon read-only.macaroon \
     --node <your-node-pubkey>
   ```

4. **Verify findings against LND UI**
   ```sh
   ./rieko status --db ~/.rieko/rieko.db
   # Cross-check findings, channel states, and recommendations against
   # what `lncli listchannels` and `lncli fwdinghistory` show.
   ```

5. **Replay — verify zero duplicates**
   ```sh
   ./rieko scan \
     --lnd-rest https://localhost:8080 \
     --tls-cert ~/.lnd/tls.cert \
     --macaroon read-only.macaroon \
     --node <your-node-pubkey>
   # Findings, recommendations, and audit entry counts must be unchanged.
   ```

6. **Restart and verify state survives**
   ```sh
   ./rieko status --db ~/.rieko/rieko.db
   # All findings, recommendations, and audit entries must still be present.
   # Alert cooldown state must be intact.
   ```

7. **Enable Telegram only after core observation works**
   ```sh
   export RIEKO_TELEGRAM_TOKEN=...
   export RIEKO_TELEGRAM_CHAT_ID=...
   ./rieko monitor \
     --lnd-rest https://localhost:8080 \
     --tls-cert ~/.lnd/tls.cert \
     --macaroon read-only.macaroon \
     --node <your-node-pubkey> \
     --interval 300
   # Let it run for at least one full cycle. Verify alerts arrive.
   ```

8. **Enable LLM only after confirming data-sharing implications**
   ```sh
   export RIEKO_LLM_ENDPOINT=https://api.openai.com/v1/chat/completions
   export RIEKO_LLM_API_KEY=sk-...
   export RIEKO_LLM_MODEL=gpt-4o-mini
   # Re-run monitor or scan. Confirm explanations appear.
   # Understand that structured evidence is sent to the LLM endpoint.
   ```

Only after all 8 steps pass should Rieko be connected to mainnet. Rieko
remains local, read-only, and observes only — it does not send transactions,
update fees, or rebalance channels.

## License

Apache-2.0
