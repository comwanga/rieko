# ADR-0006: Agent and CLI Runtime Boundary

- **Status:** Accepted
- **Date:** 2026-08-25
- **Type:** Architecture

## Context

The proven BTCPay webhook pipeline originally ran inside `rieko serve`. That
made an operator-interface command the owner of ingestion, detector execution,
finding persistence, and the local API. The approved architecture requires a
distinct long-running `rieko-agent` executable while preserving existing
deployments that invoke `rieko serve`.

## Decision

The existing `rieko-cli` package now produces two executables:

- `rieko-agent` owns the long-running Tokio runtime, BTCPay webhook ingestion,
  bounded event window, deterministic detector execution, SQLite persistence,
  local API, structured tracing, and graceful shutdown.
- `rieko` remains the operator CLI. Its existing `serve` command delegates to
  the same shared agent runtime and retains its existing arguments.

The shared runtime is implemented once in the package library. No new crate,
transport, persistence model, or adapter abstraction is introduced by this
boundary.

## Consequences

The agent is now independently executable and can become the stable daemon
boundary. Existing `rieko serve` invocations remain valid without maintaining a
second webhook processing path. Durable event replay and additional adapters
remain separate future decisions.
