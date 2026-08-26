# Real BTCPay regtest health smoke test

`live_btcpay_health` is an ignored integration test because it requires a real
BTCPay Server deployment. It never substitutes fixture or mock Greenfield
responses.

The deployment must provide:

- an HTTP endpoint reachable only inside the trusted test network;
- a regtest store with Lightning configured so the existing snapshot endpoints
  return successfully;
- a Greenfield API key restricted to the read-only permissions required for
  server information and store Lightning information/channels.

Run it with:

```bash
export BTCPAY_GREENFIELD_URL=http://127.0.0.1:23000
export BTCPAY_GREENFIELD_STORE=<regtest-store-id>
export BTCPAY_GREENFIELD_API_KEY=<scoped-read-only-key>
cargo test -p rieko-cli --test live_btcpay_health -- --ignored --nocapture
```

The test uses two identically configured, four-cycle `rieko-agent` processes. A
local TCP proxy initially forwards to the real BTCPay endpoint. After `/status`
proves a healthy persisted Greenfield observation, the test closes the proxy and
its active connections. Three subsequent polling cycles therefore observe a
real connectivity failure without reconfiguring or stopping BTCPay. The test
stops the agent with one active health finding, restarts it against the same
SQLite database, and proves the finding and disconnected operational state were
reopened. It then restores the same proxy address and waits for the existing
three-cycle resolution hysteresis. Finally, it verifies the original finding ID
becomes resolved through the authenticated API and confirms the connected
operational state and single resolved finding after reopening the database.

The existing `regtest.yml` workflow provisions this path on every run. It pins
BTCPay Server 1.13.7, NBXplorer 2.5.12, and PostgreSQL 13.13, attaches them to
the workflow's existing Bitcoin Core and LND regtest network, and creates one
ephemeral store through Greenfield. The store uses the existing LND node as its
internal Lightning node.

The workflow then creates an ephemeral store-scoped API key with only the
read-only permissions used by Rieko and supported by the pinned BTCPay release:
Lightning node access, invoice viewing, and store-settings viewing. The key is
masked before it is passed to the test and is destroyed with the containers at teardown. No GitHub
repository secret or production credential is required. The
`BTCPAY_REGTEST_SMOKE_ENABLED=true` marker is scoped only to the smoke-test
step.

The same ignored test target also exercises the first Bitcoin Core correlation
path. The workflow gives `rieko-agent` a separate RPC user whitelisted only for
`getblockchaininfo`; the existing full-access regtest credential remains test
orchestration-only. The test waits until real BTCPay and Core observations are
both healthy, submits one valid regtest header without its block while keeping
Core RPC reachable, and confirms `blocks < headers` before polling continues. It then
waits for repeated unsynchronized observations, verifies exactly one active
`bitcoin_core_sync_correlation` finding through authenticated `/findings` and
`/findings/:id`, stops the agent, and reopens SQLite to compare the persisted
finding and Core state. A cleanup guard mines past the header-only branch,
including when an assertion fails. Both live tests run
serially and each has a 30-second bound.
