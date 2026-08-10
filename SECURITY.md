# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Rieko is pre-release software. Only the latest published commit on `main`
receives security updates.

## Scope

Rieko v2 is a **read-only** operational intelligence engine with deterministic
simulation enabled by default. The default release binary cannot:

- Spend funds.
- Open, close or rebalance channels.
- Update channel fee policy.
- Mutate Bitcoin Core.

Simulation creates local projection records only — it never contacts or mutates
a node. Simulation creation is rate-limited to 5 requests per second to prevent
resource exhaustion. Draft execution types are isolated behind the
disabled-by-default `execute` feature and interlocked at runtime.

If you discover a flaw that could enable mutation in the default build, please
report it immediately.

## Reporting a vulnerability

Please report security issues privately to the project maintainer. Do not
file a public issue.

Expect an initial response within 72 hours. After the issue is confirmed,
a fix will be prepared and released as a patch. The reporter will be
acknowledged in the release notes unless they request anonymity.

## Threat model (v2)

Rieko runs on operator hardware, binds to loopback by default, and does
not accept write operations against any node.

Known assumptions:

- The operator controls the host filesystem and can read or modify the
  SQLite database directly. Rieko does not implement cryptographic tamper
  evidence for database files.
- The bearer token for non-loopback API access is a shared secret stored
  in a file or environment variable. Token comparison is constant-time.
- LND access uses a restricted read-only macaroon scoped to the exact
  endpoints Rieko needs. An admin macaroon is unnecessary and unsafe.
- LND TLS certificate trust is scoped to the individual client instance;
  global certificate verification is never disabled.
- LLM integration sends structured evidence (not raw channel data) to a
  configured endpoint. The operator is responsible for the privacy
  implications of the chosen LLM provider.
- Telegram alerts may include channel identifiers and liquidity conditions.
  Alert messages are Markdown-escaped.
- The macaroon is read as binary bytes and hex-encoded for the
  `Grpc-Metadata-macaroon` header. It is never logged, never included in
  error messages, and never stored in the audit trail.
- Simulation creates local projection records only. Parameters are validated
  before any computation. Cross-network snapshots are rejected. Stale source
  data produces a stale marking, not a silent error.
- The default binary is compiled without execution capability. CI verifies
  this via dependency tree inspection on every pull request.

## Simulation-specific guards

- Maximum 5 simulation creations per second (sliding window rate limiter)
- Request body capped at 1 MiB
- Snapshot digests and networks must match provenance
- Amount must not exceed spendable liquidity
- Source and destination must be different channels
- Future-dated observations are rejected
- Model version mismatch is rejected
- Canonical input is embedded in every record for replay verification

## Execution safety (draft, not for production)

`--features execute` exposes draft action workflow commands for development,
but execution is interlocked at runtime and not supported. The planned guards
below are not implemented:

- immutable simulation binding and freshness validation;
- durable execution idempotency and crash reconciliation;
- explicit network and mainnet gates;
- exact mutation preview and confirmation;
- fresh channel and spendable-balance checks;
- structured execution audit records;
- LND-version-specific regtest protocol validation.
