---
name: rieko-security-boundaries
description: Use when a Rieko change or review touches authentication, the bearer token, network binding, the BTCPay webhook or HMAC, macaroons, TLS, secret files, configuration, response headers or CSP, the execute feature, LLM or Telegram output, logging of identifiers, dependencies, CI or release workflows - and before running Rieko against any live node or reading any credential file.
---

# Rieko security boundaries

Rieko holds read access to Bitcoin Core, LND and BTCPay Server. Its central guarantee is
that the default build observes and never mutates a node. Treat every item below as an
invariant: a change that weakens one needs explicit approval before implementation, and
a review must check each one the diff could reach.

## Rules for the agent doing the work

- Do not read, print, copy or pass to any tool the contents of macaroons, token files,
  API-key files, webhook secrets, `/run/secrets`, `deploy/docker/secrets/` or a real
  `rieko.json`. Refer to them by path only.
- Do not run Rieko, tests or scripts against mainnet or any node you were not explicitly
  told is a disposable regtest instance. Use `fixtures/channels.json`, in-memory
  storage and the mock servers the tests already use.
- Use synthetic tokens in tests and examples. Never place a token in a URL, a log line,
  a commit, a screenshot or a Playwright trace.
- Do not build or run with `--features execute` unless the task is about that feature.

## Invariants

| # | Invariant | Where it is enforced |
|---|---|---|
| 1 | The default build has no execution path. `rieko-execution` is an optional dependency behind `execute`; even then live execution is refused at runtime. | `crates/rieko-cli/Cargo.toml`, `commands/actions.rs` (interlock and its test) |
| 2 | Non-loopback binding requires both `--allow-external` and a bearer token. | `agent.rs` (`enforce_binding_policy` and its tests) |
| 3 | Every JSON route is behind `require_auth` when a token is configured; comparison is constant-time. The webhook route is the only exemption. | `rieko-api/src/app.rs` |
| 4 | The webhook fails closed when unconfigured, verifies HMAC-SHA256 in constant time before parsing, deduplicates by delivery id, and persists before acknowledging. | `rieko-api/src/routes.rs`, `rieko-ingest-btcpay/src/webhook.rs`, ADR 0007 |
| 5 | Secrets come from files or the environment. Saved configuration stores the path of a key file, never the key. | `agent.rs` (`load_token`, `load_secret`), `commands/attach.rs`, `config.rs` |
| 6 | The LND macaroon is read as bytes, sent only as a header, and never logged, stored or put in an error. Plain `http://` is refused unless explicitly allowed. A custom TLS root is scoped to one client; certificate verification is never disabled. | `rieko-ingest-lnd/src/client.rs` and its tests |
| 7 | Responses carry `no-store`, `nosniff`, frame denial, same-origin resource policy and a CSP of `default-src 'none'` with `script-src 'self'` and `connect-src 'self'`. No CORS header is emitted. | `app.rs` (`security_headers`), `tests/hardening.rs`, `tests/embedded_ui.rs` |
| 8 | The UI keeps the token in `sessionStorage` or memory, sends it only to its own origin, never retries a request after credentials change. | `frontend/src/lib/auth.ts`, `api.ts`, `tests/api-auth.spec.ts` |
| 9 | Requests are bounded: body size, request timeout, pagination limits, simulation rate limit. | `app.rs`, `routes.rs` |
| 10 | Outbound text is constrained. The LLM prompt is built from the detector name, severity, evidence and an optional caller-supplied context string, so check what each caller puts in that context. Telegram messages are escaped. Provenance is redacted. | `rieko-llm/src/prompt.rs` and its callers, `rieko-alerts/src/telegram.rs`, `rieko-findings/src/finding.rs` |
| 11 | Simulation writes local records only and validates inputs before computing. | `rieko-simulation-app`, ADR 0005, `SECURITY.md` |

## Reviewing a change

1. List the invariants the diff can reach, including through shared helpers and
   middleware ordering in `router_with_state`.
2. For each, name the test that would fail if it were broken. An invariant with no such
   test is a finding in itself.
3. For a new route: is it inside the authenticated router, bounded, read-only, and does
   its error path avoid echoing secrets or internal paths?
4. For a new log field, evidence key, alert or LLM prompt input: could it carry a
   secret, an unredacted endpoint, or more node detail than `SECURITY.md` says leaves
   the host?
5. For a new dependency or workflow action: is it needed, pinned, and does
   `cargo audit` / `npm audit` still pass? Does the default feature set still exclude
   `rieko-execution` (`cargo tree -p rieko-cli -e normal | grep rieko-execution` should
   print nothing)?
6. Compare any security statement in `README.md` or `SECURITY.md` with the code and the
   workflows. A documented control that you cannot find is a finding; do not repeat the
   claim as fact.

## Reporting

State for each invariant touched: preserved, weakened or strengthened, with `file:line`
and the test that demonstrates it. Mark anything you did not run as not verified. Use
the built-in `/security-review` for a general pass over a diff; this skill supplies the
Rieko-specific invariants that pass must not miss.
