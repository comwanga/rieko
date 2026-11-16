---
name: rieko-surface-parity
description: Use when a Rieko change adds, removes, renames or reshapes anything another part depends on - an HTTP route, a response or error shape, a serialized enum or struct, a CLI command, flag or JSON output, a detector, a config key, an environment variable, a database schema version, or a documented guarantee - and when the UI or CLI shows wrong, missing or "unrecognised" values after a backend change.
---

# Rieko surface parity

Rieko has one backend and several consumers that are not type-checked against it: the
Svelte UI declares its own TypeScript copies of the Rust types, the CLI reads the same
API, and the README and deployment docs state the contract in prose. Nothing fails at
compile time when they drift, so parity is a manual step in every change to a surface.

## What moves together

| If you change | Also check |
|---|---|
| A route or its parameters (`crates/rieko-api/src/app.rs`, `routes.rs`) | `frontend/src/lib/api.ts` and callers; CLI commands in `crates/rieko-cli/src/commands/`; the endpoint table in `README.md`; tests in `crates/rieko-api/tests/` and `frontend/tests/` |
| A serialized type or enum variant (`rieko-findings`, `rieko-domain`, `rieko-status`, simulation views) | the matching TypeScript type in `api.ts` or `overview.ts`; loose runtime mappers such as `describeProvenance` in `frontend/src/lib/findings.ts`; CLI output structs; golden fixtures |
| An error response | both shapes in use (plain text from `(StatusCode, String)` handlers, JSON `{ "error": { "code", "message" } }` from others) and how `request()` in `api.ts` reads them |
| A CLI command or flag | `README.md`, `docs/deploy-*.md`, `deploy/docker/config/rieko.json.example`, `deploy/systemd/rieko-agent.service`, `DEPLOYMENT.md` |
| A detector (id, version, thresholds, evidence keys) | the detectors table in `README.md`, any `docs/` page for it, UI code that reads evidence keys, recommendation rules keyed on the detector |
| The database schema (`rieko-storage/src/migrations.rs`) | migration tests, `schema_version` in status, `FINDING_SCHEMA_VERSION` when finding fields change, the upgrade note in `README.md` |
| A security or safety property | `SECURITY.md`, the README sections that restate it, the ADR it comes from, and the test or CI step that enforces it |
| User-visible behaviour | `CHANGELOG.md` |

Serde attributes decide the wire form (`rename_all`, `tag`, `skip_serializing_if`, or the
default externally tagged form). Read the attribute; do not guess the JSON.

## Method

1. Name the surface and its old and new form.
2. Search for the old name, the route path and the variant string across `crates/`,
   `frontend/`, `docs/`, `deploy/` and the top-level Markdown files.
3. Update each mirror in the same change, or state which is deferred and why.
4. For a new enum variant, check what each consumer does with a value it does not know.
   It should show the raw value, never a healthy-looking default.
5. Add or extend a test at the boundary that would have caught the drift.

## Drift you find but did not cause

Report it with both locations and what a user would see. Do not fix it inside an
unrelated change; it is its own piece of work and needs its own approval.

## Reporting

List each mirror as updated, unaffected (with the reason) or deferred. "Unaffected"
requires that you searched, and says what you searched for.
