# ADR 0007: Durable BTCPay webhook handoff

- Status: Accepted
- Date: 2026-08-25

## Context

The BTCPay webhook route previously acknowledged a delivery after placing its
normalized event on an in-memory channel. A process exit after acknowledgment
could therefore lose the event before the detector cycle persisted its
findings.

## Decision

Persist each normalized BTCPay event together with its delivery record before
returning a successful webhook response. The runtime treats the bounded Tokio
channel as a wake-up signal and drains pending events from storage at startup
and after each notification.

Mark an event processed in the same storage transaction that applies the
detector cycle's finding changes. If that transaction fails, leave the event
pending and restore the in-memory detector window so it can be retried.

On startup, reconstruct the detector's existing 100-event bounded window from
the most recently accepted processed events in the same table before draining
pending events.

## Consequences

- Accepted webhook deliveries survive agent restarts until their detector
  cycle commits.
- Duplicate delivery identifiers remain idempotent.
- Queue saturation no longer rejects an event that was already persisted.
- Detector evidence remains continuous across orderly processing and agent
  restarts without a second event-history mechanism.
