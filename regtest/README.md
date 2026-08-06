# LND regtest integration (Phase 6)

These tests validate Rieko against a real LND node in regtest mode.
They are **opt-in**: ignored by default, require explicit environment
configuration, and never connect to mainnet.

## Prerequisites

1. A running LND node in regtest (or simnet) with the REST API enabled.
2. A **restricted read-only macaroon** scoped to:
   ```
   uri:/lnrpc.Lightning/Channels
   uri:/lnrpc.Lightning/ForwardingHistory
   ```
   Do **not** use `admin.macaroon`.

3. The LND TLS certificate (`tls.cert`).

## Quick start

```sh
export RIEKO_REGTEST_LND_URL=https://localhost:8080
export RIEKO_REGTEST_TLS_CERT=/path/to/lnd/tls.cert
export RIEKO_REGTEST_MACAROON=/path/to/read-only.macaroon
export RIEKO_REGTEST_NODE_ID=<your-node-pubkey>

cargo test -p rieko-ingest-lnd --test regtest -- --ignored --nocapture
```

## Setting up a regtest LND node (optional helper)

If you use [Polar](https://lightningpolar.com/) or a manual regtest setup,
verify the REST API is accessible:

```sh
# Check the REST API is reachable
curl -k https://localhost:8080/v1/channels \
  --header "Grpc-Metadata-macaroon: $(xxd -p -c 10000 read-only.macaroon)"
```

## What the tests verify

| Test | What it checks |
|------|---------------|
| `regtest_read_only_surface_accepts_restricted_macaroon` | Restricted macaroon grants access |
| `regtest_raw_channels_match_normalized_channels` | Every raw LND channel maps to one normalized domain channel |
| `regtest_channel_status_is_not_unknown` | LND flag→status mapping covers all expected flags |
| `regtest_forwarding_resolves_channel_ids` | SCID resolution works with real LND data |
| `regtest_rejects_wrong_tls_certificate` | Wrong TLS cert is rejected (no silent bypass) |
| `regtest_insufficient_macaroon_is_rejected` | Empty/insufficient macaroon fails |
| `regtest_source_freshness_is_reported` | Channel timestamps are recent |
| `regtest_node_mismatch_is_detectable` | Node ID mismatch is verifiable |

## CI integration (future)

To run these in CI, provision a regtest LND container and supply the
environment variables. This is intentionally not wired into the default
CI pipeline to keep the fast path independent of external services.
