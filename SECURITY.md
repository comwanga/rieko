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

Deterministic simulation is enabled by default and remains read-only. Draft v3
types are isolated behind the disabled-by-default `execute` feature. Live
execution is additionally interlocked at runtime and is not supported.

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

## Execution safety (draft feature)

`--features execute` exposes draft action workflow commands for development,
but `actions execute` refuses before opening the database, loading credentials,
or constructing an LND mutator. The planned guards below are not implemented
and must not be treated as current capabilities:

- immutable simulation binding and freshness validation;
- durable execution idempotency and crash reconciliation;
- explicit network and mainnet gates;
- exact mutation preview and confirmation;
- fresh channel and spendable-balance checks;
- structured execution audit records;
- LND-version-specific regtest protocol validation.
