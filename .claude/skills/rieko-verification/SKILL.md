---
name: rieko-verification
description: Use when about to say a Rieko change works, is fixed, passes, or is ready for review - and when choosing which tests, lints or builds to run for a change, reproducing a CI failure locally, or deciding whether a claim counts as verified.
---

# Rieko verification

This skill maps a change to the checks that cover it and fixes the words used to report
the result. It does not restate general engineering principles from your instructions
file; it applies them to this repository.

## What to run

Run from the repository root unless a directory is given. Record the command and its
actual result.

| Change touches | Run |
|---|---|
| Any Rust | `cargo fmt --check` · `cargo clippy --workspace --all-features -- -D warnings` · `cargo test -p <crate>` for each changed crate |
| Shared crates (`rieko-domain`, `rieko-findings`, `rieko-storage`, `rieko-graph`) or anything before review | `cargo test --workspace --all-features` |
| `rieko-api` routes, middleware, headers | `cargo test -p rieko-api` (covers `hardening`, `embedded_ui`, webhook, simulation and inspection suites) |
| Agent runtime, CLI commands | `cargo test -p rieko-cli` · `cargo test -p rieko-cli --test release_e2e` |
| Migrations or SQLite code | `cargo test -p rieko-storage` including the migration tests; state the schema version before and after |
| Detectors, findings, recommendations | `cargo test -p rieko-detectors -p rieko-findings -p rieko-recommendations` and the agent-level lifecycle tests in `rieko-cli` |
| Simulation | `cargo test -p rieko-simulation -p rieko-simulation-app` (golden fixtures must not change unless the model version does) |
| Anything in `frontend/` | in `frontend/`: `npm run check` · `npm run build` |
| UI behaviour, auth flow, security headers, embedded assets | build first (`npm run build`, then `cargo build -p rieko-cli`), then in `frontend/`: `npm run test:browser` |
| Dependencies | `cargo audit --deny warnings` · in `frontend/`: `npm audit --audit-level=high` |
| Feature gating | `cargo tree -p rieko-cli -e normal` contains no `rieko-execution` in the default feature set |

Notes:

- CI (`.github/workflows/ci.yml`) is the reference for order and flags. If a command
  here disagrees with it, CI wins and this file should be corrected.
- The browser suite needs Chromium (`npx --no-install playwright install chromium`) and
  the built `rieko` and `rieko-agent` binaries. If either is missing, report the suite
  as not run; do not substitute a different check and call it equivalent.
- Live tests need the regtest stack from `.github/workflows/regtest.yml`:
  `live_btcpay_health` is `#[ignore]`, and `rieko-ingest-lnd/tests/live_regtest.rs`
  returns early unless `LND_REST` is set. Never set those variables to a real node.
  Locally these are normally "not run", and a silently skipped live test is not a pass.
- `cargo install`, `npm ci` and `playwright install` change the machine. Ask before
  running them if the tool is not already present.
- A failing check that also fails on the base commit is pre-existing: show both runs.

## Words for results

Use exactly one of these for each claim, and do not upgrade one into another.

| Level | It means | Minimum evidence to cite |
|---|---|---|
| Runtime-confirmed | You ran the built program and observed the behaviour | command, relevant output |
| Test-confirmed | An automated test exercised it and passed or failed | test name, pass/fail line |
| Statically checked | Compiler, clippy, `svelte-check` or audit accepted it | command and result |
| Source-supported | You traced the code path and it implies the behaviour | `file:line` chain |
| Hypothesis | Plausible, not yet traced or tested | what would confirm or refute it |
| Not verified | A check you could not or did not run | which check and why |

Reading code is never "tested". A passing unit test is never "works in the running
agent". A test that passes without exercising the changed line confirms nothing about it:
for a bug fix, show the new test failing before the fix and passing after.

## Before reporting completion

1. Baseline known: what passed before your change?
2. Every row of the table that matches your diff has a recorded result or an explicit
   "not verified".
3. `git status` and `git diff --stat` show only intended files.
4. Surfaces changed are mirrored (see `rieko-surface-parity`); security invariants
   reached are checked (see `rieko-security-boundaries`).
5. The report lists what was verified at which level, what was not, and what remains
   uncertain. Committing, pushing and opening a pull request need separate approval.
