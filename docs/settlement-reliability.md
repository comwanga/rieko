# Settlement reliability (detector v2)

The agent evaluates invoice evidence on arrival and every minute. Its default
window is the last 60 minutes of normalized webhook timestamps. Configure it with
`--btcpay-settlement-window-minutes` on `rieko-agent` or `rieko serve` (1–10080
minutes). Future timestamps are excluded; the lower window boundary is inclusive.

Each store/invoice pair contributes at most once, regardless of duplicate
deliveries or the number and arrival order of its lifecycle events:

| Evidence | Classification |
|---|---|
| Expired with `partiallyPaid: true` | Failure |
| Invalid with `manuallyMarked: false` | Failure |
| Payment received with `afterExpiration: true` | Failure |
| Settled with `manuallyMarked: false` | Settled |
| Expired with `partiallyPaid: false` | Abandoned checkout; excluded |
| Processing, or payment received before expiration | Pending; excluded |
| Missing classification flag, or manually marked outcome | Unknown; excluded |

If both failure and settlement evidence occur for an invoice within the window,
it counts as one failure. This measures an invoice experiencing a failure during
the window, even if it later recovered. Known failure or settlement evidence
takes precedence over unknown and pending events. An abandoned expiry without
other conclusive evidence is excluded. Legacy events still decode; absent flags
remain unknown rather than becoming false or being inferred from amounts.

The rate is `failed / (failed + settled)`. At least two failed invoices are
required. Warning begins at 40%, and Critical begins at 70%. These defaults are
heuristics, not proof of an infrastructure outage. Five failures alone do not
force Critical severity. Evidence includes failed, settled, abandoned, unknown
and pending counts, window boundaries and thresholds. `expired_invoices` counts
only partially paid expiries; `failed_invoices` also includes invalid and late
payment evidence.

When evidence leaves the window, periodic evaluations can clear a finding without
new invoices. Resolution still requires three complete clean cycles. Individual
delivery writes cannot advance resolution while replay is partial. A successful
drain reconciles once; an idle timer tick also reconciles once. The final pending
check and reconciliation share the storage lock used by webhook admission. Restart
recovery restores all processed events in the time window; it does not truncate
the detector's history to the last 100 events. Pending delivery batches remain
bounded, and delivery processing commits atomically with its detector cycle.

Finding identities use detector version 2. Version 1 findings resolve through the
same scoped lifecycle reconciliation. The agent's settlement worker does not yet
receive fresh Core/LND correlation inputs; its root cause remains undetermined.
That integration belongs to the later correlation milestone.
