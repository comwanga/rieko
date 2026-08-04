# ADR-0001: Rieko v1 — Operational Intelligence Engine Architecture

- **Status:** Accepted
- **Date:** 2026-08-05
- **Deciders:** Owner
- **Type:** Architecture (foundational, multi-decision)

## Context

Rieko is being positioned as an **operational intelligence engine for Bitcoin/Lightning infrastructure** — not an AI application. AI (LLM explanation, later anomaly models) is one capability inside the engine. The goal of v1 is a single, shippable wedge: a self-hosted engine that observes a node operator's environment, explains anomalies in plain language, and recommends actions.

This ADR freezes the foundational architecture so the v1 build can proceed without re-litigating stack decisions. It records the decisions already converged on in design review.

## Decisions

### D1 — Rieko is an intelligence engine, not an AI product
The value is detection, correlation, and operational decisions. LLMs are used only to *summarize structured evidence* into plain-language findings — never as the detector. Detectors emit typed findings with structured evidence; the LLM produces the human-readable layer on top.

### D2 — Language-per-layer, one production runtime
- **Rust** — engine, graph, detectors, LLM client, API (axum). Single static binary. Production runtime only.
- **Python** — *offline only*: experimentation, backtesting, statistical model development, ONNX model export. No Python server ships.
- **TypeScript** — frontend only (Svelte + TanStack Query), served by the Rust binary.

This keeps production ops to exactly one runtime, which is the on-prem adoption story.

### D3 — Frozen deployment shape
One binary. **No Node server, no Python server, no Redis, no Kafka, no Kubernetes, no microservices, no message broker.**
- Storage: SQLite (with WAL), behind a storage trait.
- API: Rust axum, serving the API and static frontend assets.
- Deployment: self-hosted on operator hardware; read-only by default at v1.

### D4 — Domain layer as the kernel
Ingesters never feed detectors raw LND objects. The pipeline is:

```
LND / Core ──▶ Normalizers ──▶ Domain Objects ──▶ Graph ──▶ Detectors
```

Domain objects carry **operational semantics** (`Channel.liquidity_profile`, `health`, `risk_state`), not just re-typed protobufs. The domain model is the protocol-agnostic contract; new sources (CLN, LDK, Eclair) are added as normalizers without touching detectors. A raw-event escape hatch exists for detectors that genuinely need protocol-specific data.

### D5 — Modular crates with enforced dependency direction
Crates split as:
```
crates/
  rieko-domain        (kernel — depends on nothing)
  rieko-graph         (kernel — depends on rieko-domain only)
  rieko-storage       (SQLite impl behind trait)
  rieko-ingest-core   (Bitcoin Core normalizer)
  rieko-ingest-lnd    (LND normalizer)
  rieko-detectors     (domain → findings)
  rieko-findings      (typed findings model)
  rieko-recommendations
  rieko-alerts        (with dedup/cooldown)
  rieko-llm           (explanation client)
  rieko-api           (axum)
  rieko-cli
```
Enforced rule: **`rieko-domain` and `rieko-graph` depend on nothing; everything else depends on them.** This kernel is the reusable core intended to be shared with future BitScope/Twiga integrations.

### D6 — SQLite-first storage
Start with SQLite + WAL only. Storage sits behind a trait to allow the proven progression later: `SQLite → SQLite+WAL → DuckDB (analytics) → PostgreSQL (multi-node/cloud)`. RocksDB is not considered until a demonstrated need exists.

### D7 — Action model progression, built from day one
The action model is designed as `Observe → Explain → Recommend → Simulate → Approve → Execute` even though v1 only reaches **Recommend**.
- Every finding maps to a typed action with a status field.
- Every action is appended to an **audit log**, including read-only recommendations.
- v2 = Simulate. v3 = Approve/Execute (explicit human approval only).

### D8 — Build order: one vertical slice, not five detectors
v1 ships **one detector end-to-end first**: channel liquidity / imbalance.
```
Ingest → Normalize → Store → Detect → Finding → LLM explanation → Alert (Telegram)
```
Only after the full path works does detector #2 start.

### D9 — Non-negotiable v1 engineering constraints
1. **Alert dedup + cooldown + severity tiers** — alert fatigue kills ops tools; the muted bot is the dead bot.
2. **Idempotency and replay** — ingesters reconnect and resync; graph upserts are idempotent with a per-source "last seen" ledger to prevent double-counting.
3. **Self-observability** — structured logs and a `rieko status` endpoint from day one; the tool going quiet during an incident is the worst failure mode.
4. **Rules-first detection** — statistical/anomaly models are experiments exported via ONNX, never the v1 detector path.

## Consequences

**Positive**
- Minimal operational surface: one binary, one runtime, self-hostable.
- Protocol-agnostic core makes multi-source (CLN/Eclair/exchange) and reuse (BitScope/Twiga) tractable.
- Action model + audit log pre-position the product for enterprise trust and the Simulate/Execute roadmap.
- SQLite-only keeps early shipping velocity maximal.

**Negative**
- Domain abstraction costs upfront design effort and must not become a thin re-typing layer (guarded by D4 semantics).
- Single-binary constraint caps multi-node/analytics features until a proven need justifies Postgres/DuckDB.
- LLM explanation quality needs an eval set of real incidents to keep the "explain" promise honest.

## Follow-ups (explicitly out of scope for this ADR)
- Detector #2 selection (after liquidity slice ships)
- Security intelligence feed (version/CVE/gossip correlation) — v1.5
- PoR / compliance report engine — post-v1, same graph
