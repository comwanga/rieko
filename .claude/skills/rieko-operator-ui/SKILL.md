---
name: rieko-operator-ui
description: Use when building, changing, reviewing, or auditing anything in Rieko's frontend - a Svelte page or component, the Overview or Services cards, findings, recommendations or simulation views, status badges, tables, loading, error, empty or stale states, navigation, layout, theme tokens, UI copy, or any chart, timeline or other visualization of operational data.
---

# Rieko operator UI

The UI is read by an operator deciding whether their Bitcoin infrastructure needs
attention. The measure of a screen is whether it lets them tell, quickly and without
being misled, what was observed, when, and what is merely inferred or projected.
Density and clarity matter; decoration does not.

## The stack as it is

- Svelte 5 with Vite and TypeScript, `@tanstack/svelte-query` for server state, a small
  hash router (`src/lib/router.ts`), plain CSS with design tokens in `src/app.css`.
- No component library, no Tailwind, no chart library, no web fonts. Do not add one, or
  any dependency, without approval; do not propose a framework migration.
- Existing components use legacy syntax (`export let`, `$:`, `on:click`, stores). A file
  is either legacy or runes, never both. Match the file you are editing. Use runes for
  a new file. Do not convert a component as a side effect of another change.
- The server sends `default-src 'none'; script-src 'self'; connect-src 'self'`. Anything
  loaded from another origin, and any inline script, will be blocked. Assets must be
  bundled.
- All requests go through `src/lib/api.ts`. Never call `fetch` directly, and never put
  the token anywhere except where `src/lib/auth.ts` puts it.

## Where logic goes

Mapping from API responses to what is displayed lives in pure functions under
`src/lib/` (`overview.ts`, `findings.ts`), which return view models and are covered by
`tests/*-model.spec.ts`. Components render models. Put new display logic, formatting
and state classification there, with tests, so a wrong label is caught without a browser.

## Truthfulness rules

1. Every displayed value comes from a field of a response. An absent field produces no
   row. No placeholder numbers, no sample data, no value invented to fill a layout.
2. Distinguish the kinds of data wherever they appear together:
   **observed** (with its observation time), **derived** (computed from observed
   values), **simulated** (a deterministic projection; carry the "no action was
   executed" statement), and **heuristic** (thresholds and severities).
3. Use the existing vocabulary for source state: Not observed, Never connected,
   Connected, Disconnected. When a source is disconnected, values are labelled as last
   known and the last attempt is shown.
4. A status must say what it covers. The pipeline badge describes Rieko's own pipeline,
   not the health of every system; keep that distinction in any new summary.
5. Show limits. If a list is capped, say so (`50+`, "may be incomplete").
6. Times show both relative and absolute forms. Amounts state their unit (msat or sats)
   and are not rounded in a way that hides a difference the operator would act on.
7. Unknown enum values from the backend render as themselves, never as a default that
   looks healthy.

## States every data view needs

Loading; error (with `role="alert"` and the server's message); empty (say what would
make it non-empty); authentication required; stale or last-known. Decide each one
explicitly, including for a partial failure where one of several requests fails.

## Accessibility and interaction

Load the `accessibility` skill for criteria and patterns. Conventions already in place
that new work must keep: focus moves to the view's `h2` after navigation, a skip link,
a visible `:focus-visible` outline from the `--focus` token, status conveyed by text as
well as colour, native elements for interaction. Every action must work from the
keyboard. Text colours come from tokens chosen for contrast in both themes; a new colour
needs a contrast check in dark and light. When auditing, do not install global tools;
use the Playwright setup already in `frontend/`.

## Visual design

Use the tokens in `app.css` (`--space-*`, surface, text, status and focus colours). No
raw hex in components. Changes should make information easier to scan: alignment,
grouping, hierarchy, consistent badges, tabular numbers. Do not add gradients, glass
effects, decorative motion or new typefaces. For Svelte idiom, load
`svelte-core-bestpractices`.

## Charts and visualizations

There are none today, so the first one sets the pattern. Load the `dataviz` skill, then:

- Choose the form from the question the operator is asking; a table is often right.
- Draw from stored snapshots only. Mark gaps where no observation exists; never
  interpolate across an interval in which the source was not observed.
- Observed series and projected or simulated series must differ in more than colour
  (line style and a text label), with the snapshot time of the projection's input.
- Thresholds drawn on a chart are labelled as heuristics with their values.
- Provide the same data as text or a table, and an accessible name and description.
- Inline SVG with existing tokens; a charting dependency needs approval.

## Reporting a UI review

For each issue: the file and line, what the operator would see, why it misleads or
blocks them, and whether you observed it in a running browser or inferred it from source.
