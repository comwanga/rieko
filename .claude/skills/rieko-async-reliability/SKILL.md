---
name: rieko-async-reliability
description: Use when reviewing, debugging, or changing Rieko's agent runtime or any async Rust in it - poll loops, tokio::select!, spawn_blocking, the shared storage mutex, timeouts, graceful shutdown, webhook handoff and replay, hung or flaky async tests, lost or duplicated events, or a request that times out while storage is busy.
---

# Rieko async reliability

Rieko's runtime correctness rests on a small number of deliberate patterns. Check a
change against them before proposing anything new. Read the code first: line numbers
drift, the patterns do not.

## How the runtime is built

| Concern | Pattern in the code | Where |
|---|---|---|
| Storage access | One `Arc<tokio::sync::Mutex<Box<dyn Storage + Send>>>` shared by the API and every worker. SQLite work is blocking and never runs on the executor. | `rieko-api/src/app.rs` (`block_storage`), `rieko-cli/src/agent.rs` |
| API storage calls | `block_storage`: lock admission bounded by `REQUEST_TIMEOUT`, then `spawn_blocking` with the owned guard. | `app.rs` |
| Worker storage calls | `spawn_blocking` + `blocking_lock()` inside the closure. | `agent.rs` |
| Uncancellable writes | Dropping a `spawn_blocking` future does not stop the closure. Simulation creation is therefore exempt from the request timeout so a client never gets a timeout followed by a late commit. | `app.rs` (`request_timeout`) |
| Poll loops | `interval` with `MissedTickBehavior::Skip`; `select!` between a `watch` shutdown signal and the tick; the remote call wrapped in `tokio::time::timeout`; every outcome (success, error, timeout) persisted before the detector runs. | `agent.rs` (`run_*_poll_loop`) |
| Shutdown | axum graceful shutdown sets the `watch` flag; each worker is awaited for `WORKER_SHUTDOWN_TIMEOUT`, then aborted. | `agent.rs` (`run_until`, `stop_worker`) |
| Webhook handoff | The delivery is persisted before the HTTP acknowledgement. The mpsc send is only a wake-up (`try_send`); the worker drains durable pending rows on wake-up, on each tick and on restart. | `rieko-api/src/routes.rs` (`btcpay_webhook`), ADR 0007 |
| Complete cycles | The final "nothing pending" check and the reconciling write happen under one lock hold, the same lock webhook admission uses. | `agent.rs` (`try_persist_complete_settlement_cycle`) |
| Transactions | Explicit `begin/commit/rollback` on the trait object, all inside one blocking closure, rollback on every error path. | `agent.rs` (`persist_finding_cycle`) |
| Single writer | A process holding any ingest source takes the database writer lock; a second monitor is refused at startup. | `agent.rs`, `rieko-storage/src/sqlite.rs` |
| Blocking HTTP | The LND client is `reqwest::blocking` and must be dropped outside the async context. | `agent.rs` (end of `run_lnd_poll_loop`) |

## Audit questions

Answer each from the code, citing `file:line`.

1. **Blocking**: does any new code call storage, `std::fs`, or a blocking client from an
   async context without `spawn_blocking`? Does any `await` happen while a storage
   guard is held?
2. **Lock scope**: is a check and the write that depends on it done under one lock hold?
   Splitting them across two `spawn_blocking` calls reopens the admission race.
3. **Cancellation**: can this future be dropped by `timeout` or `select!` between a
   state change and its completion? In-memory state changed before an `await` must be
   restored on failure (see how `process_pending_webhook_event` restores the window).
4. **Timeout meaning**: when a timeout fires, what is still running? A timed-out
   `spawn_blocking` task continues; say what it can still write.
5. **Durability**: is anything acknowledged, logged as done, or removed from a queue
   before its transaction commits? Would a crash at each `await` lose or duplicate it?
6. **Shutdown**: does every new loop observe the shutdown signal, and can its body
   finish inside `WORKER_SHUTDOWN_TIMEOUT`? An aborted worker must leave no half-applied state.
7. **Failure state**: is a failed or timed-out poll recorded so the UI shows
   "Disconnected" with last-known values instead of stale data that looks current?
8. **Backpressure**: is every channel bounded, and is a full channel safe because the
   durable queue is the source of truth?
9. **Time**: is wall-clock time read once and passed down? Detectors take
   `evaluated_at`; they do not read a clock.
10. **Tests**: is there a test that exercises the failure or race, in the style of the
    existing `agent.rs` tests (mock axum server, bounded `cycles`, in-memory or SQLite storage)?

## Reporting

Classify every statement:

- **Confirmed by test or reproduction**: name the test and its result.
- **Supported by source**: the code path, with `file:line`, and why it leads to the behaviour.
- **Hypothesis**: what would have to be true, and the experiment that would settle it.

A race described from reading code is "supported by source" until a test reproduces it.
Do not propose restructuring (a new channel, actor, or lock type) unless a specific
answer above shows the current pattern cannot be made correct with a local change.
