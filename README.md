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

Against a live node:

```sh
cargo run -- scan --lnd-rest https://localhost:8080 \
  --macaroon admin.macaroon --node <your-node-pubkey>
```

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
# or against a live node: --lnd-rest https://localhost:8080 --macaroon admin.macaroon
```

Inspect stored state and serve the read-only API, plus the built UI:

```sh
cargo run -- status --db ~/.rieko/rieko.db
cargo run -- serve --db ~/.rieko/rieko.db --addr 127.0.0.1:8080 \
  --static-dir frontend/dist
# UI at http://127.0.0.1:8080/  (build it first with `npm run build` in frontend/)
# GET /status, /findings, /findings/channel/{id}, /recommendations,
#     /simulations, /audit, /snapshots, /snapshots/channel/{id}
```

## License

Apache-2.0
