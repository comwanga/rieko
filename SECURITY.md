# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Rieko is pre-release software. Only the latest published commit on `main`
receives security updates.

## Scope

Rieko v1 is a **read-only** operational intelligence engine. The release
binary cannot:

- Spend funds.
- Open, close or rebalance channels.
- Update channel fee policy.
- Mutate Bitcoin Core.

The `future` feature gate (disabled by default) enables simulation and
execution capabilities (v2/v3). These are post-v1 and require explicit
operator opt-in via `--features future` at build time.

If you discover a flaw that could enable mutation in the default v1 build,
please report it immediately.

## Reporting a vulnerability

Please report security issues privately to the project maintainer. Do not
file a public issue.

Expect an initial response within 72 hours. After the issue is confirmed,
a fix will be prepared and released as a patch. The reporter will be
acknowledged in the release notes unless they request anonymity.

## Threat model (v1)

Rieko runs on operator hardware, binds to loopback by default, and does
not accept write operations.

Known assumptions:

- The operator controls the host filesystem and can read or modify the
  SQLite database directly. Rieko does not implement cryptographic tamper
  evidence for database files.
- The bearer token for non-loopback API access is a shared secret stored
  in a file or environment variable (`RIEKO_API_TOKEN`). Token comparison
  is constant-time.
- LND access uses a **restricted read-only macaroon** scoped to the exact
  endpoints Rieko needs (`Lightning.Channels` and
  `Lightning.ForwardingHistory`). An admin macaroon is unnecessary and
  unsafe.
- LND TLS certificate trust is scoped to the individual `reqwest::Client`
  instance; global certificate verification is never disabled. No
  `danger_accept_invalid_certs` anywhere.
- LLM integration sends structured evidence (not raw channel data) to a
  configured endpoint. The operator is responsible for the privacy
  implications of the chosen LLM provider.
- Telegram alerts may include channel identifiers and liquidity
  conditions. The operator decides what severity threshold triggers an
  alert. Alert messages are Markdown-escaped.
- The macaroon is read as binary bytes and hex-encoded for the
  `Grpc-Metadata-macaroon` header. It is never logged, never included in
  error messages, and never stored in the audit trail.

## Execution safety (future feature)

When `--features future` is enabled, the `actions execute` command can
mutate LND state. The following guards apply:

- Execution requires explicit human approval (`--actor` must be a non-empty,
  non-system string).
- Every execution is audited with the actor identity, action details, and
  payment hash.
- Mainnet execution requires `--allow-mainnet` flag.
- Simulation preview is mandatory before execution.
- Pre-flight checks verify the channel is open and has sufficient balance.
- Single-hop rebalances only (no multi-hop — see ADR-0002).
- No rollback mechanism for rebalances (documented limitation).
