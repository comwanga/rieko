<script lang="ts">
  import Icon from "./Icon.svelte";
  import type { CardModel, Row } from "./overview";

  export let title: string;
  export let icon: "blocks" | "bolt" | "store" | "database";
  export let model: CardModel | undefined;
  export let loading: boolean;
  export let error: string | null;

  const id = `card-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
</script>

<section class="card service" aria-labelledby={id}>
  <div class="head">
    <span class="icon"><Icon name={icon} /></span>
    <h3 {id}>{title}</h3>
    {#if model && !error}<span class="badge {model.badge.kind}">{model.badge.label}</span>{/if}
  </div>

  {#if error}
    <p class="problem" role="alert">Unavailable: {error}</p>
  {:else if !model}
    {#if loading}<p class="muted">Loading…</p>{/if}
  {:else}
    {#if model.lastKnown}<p class="muted">Last known values</p>{/if}
    {#if model.rows.length}{@render list(model.rows)}{/if}
    {#if model.records}
      <h4>Stored records</h4>
      {@render list(model.records)}
    {/if}
    {#each [model.observed, model.attempt] as time}
      {#if time}
        <p class="muted time">{time.label} {time.relative} <small>({time.absolute})</small></p>
      {/if}
    {/each}
  {/if}
</section>

{#snippet list(rows: Row[])}
  <dl>
    {#each rows as row}
      <div><dt>{row.label}</dt><dd class:mono={row.mono}>{row.value}</dd></div>
    {/each}
  </dl>
{/snippet}

<style>
  .service { display: flex; flex-direction: column; gap: var(--space-2); min-width: 0; }
  .head { align-items: center; display: flex; gap: var(--space-2); }
  .icon { color: var(--accent); display: flex; }
  h3 { flex: 1; font-size: 1rem; margin: 0; }
  h4 { color: var(--text-muted); font-size: 0.75rem; letter-spacing: 0.04em; margin: var(--space-2) 0 0; text-transform: uppercase; }
  dl { display: grid; gap: var(--space-1); margin: 0; }
  dl div { display: flex; flex-wrap: wrap; font-size: 0.85rem; gap: 0 var(--space-3); justify-content: space-between; }
  dt { color: var(--text-muted); }
  dd { margin: 0; min-width: 0; overflow-wrap: anywhere; text-align: right; }
  .mono { flex-basis: 100%; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.78rem; text-align: left; }
  .time { margin: 0; }
  p { margin: 0; }
  .problem { color: var(--critical-text); font-size: 0.85rem; overflow-wrap: anywhere; }
</style>
