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

The test starts `rieko-agent` with seven one-second polling cycles. A local TCP
proxy initially forwards to the real BTCPay endpoint. After `/status` proves a
healthy persisted Greenfield observation, the test closes the proxy and its
active connections. Three subsequent polling cycles therefore observe a real
connectivity failure without reconfiguring or stopping BTCPay. It then restores
the same proxy address and waits for the existing three-cycle resolution
hysteresis. The test verifies the original finding becomes resolved through the
authenticated API, stops the agent, and confirms the connected operational
state and single resolved finding after reopening the test database.

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
