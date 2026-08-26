# Real BTCPay regtest health smoke test

`live_btcpay_health` is an ignored integration test because it requires a real,
pre-provisioned BTCPay Server deployment. It never substitutes fixture or mock
Greenfield responses.

The deployment must provide:

- an HTTP endpoint reachable only inside the trusted test network;
- a regtest store with Lightning configured so the existing snapshot endpoints
  return successfully;
- a Greenfield API key restricted to the read-only permissions required for
  server information, store Lightning information/channels, and the on-chain
  wallet view.

Run it with:

```bash
export BTCPAY_GREENFIELD_URL=http://127.0.0.1:23000
export BTCPAY_GREENFIELD_STORE=<regtest-store-id>
export BTCPAY_GREENFIELD_API_KEY=<scoped-read-only-key>
cargo test -p rieko-cli --test live_btcpay_health -- --ignored --nocapture
```

The test starts `rieko-agent` with four one-second polling cycles. A local TCP
proxy initially forwards to the real BTCPay endpoint. After `/status` proves a
healthy persisted Greenfield observation, the test closes the proxy and its
active connections. Three subsequent polling cycles therefore observe a real
connectivity failure without reconfiguring or stopping BTCPay. The test then
requires authentication on `/findings`, verifies one typed health finding and
its evidence, stops the agent, and verifies the same finding directly in the
test database.

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
