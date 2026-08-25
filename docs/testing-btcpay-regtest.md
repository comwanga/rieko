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

The existing `regtest.yml` workflow exposes this path when the repository
variable `BTCPAY_REGTEST_SMOKE_ENABLED` is `true`. Configure
`BTCPAY_REGTEST_URL` and `BTCPAY_REGTEST_STORE` as repository variables and
`BTCPAY_REGTEST_API_KEY` as a repository secret. The URL must resolve from the
GitHub runner to the pre-provisioned regtest deployment.
