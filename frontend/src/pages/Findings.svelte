<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { derived, writable } from "svelte/store";
  import { get, type Finding } from "../lib/api";
  import { staleNote } from "../lib/findings";
  import { findingsCount, formatTime } from "../lib/overview";
  import { findingHref } from "../lib/router";

  type Lifecycle = "active" | "resolved" | "all";
  const FILTERS: { value: Lifecycle; label: string }[] = [
    { value: "active", label: "Active" },
    { value: "resolved", label: "Resolved" },
    { value: "all", label: "All" },
  ];
  const LIMIT = 200;

  const lifecycle = writable<Lifecycle>("active");
  const q = createQuery(derived(lifecycle, value => ({
    queryKey: ["findings", "list", value],
    queryFn: () => get<Finding[]>(`/findings?lifecycle=${value}&limit=${LIMIT}`),
    refetchInterval: 15000,
  })));

  const stamp = (..._updates: number[]) => new Date();
  $: now = stamp($q.dataUpdatedAt);
  $: noun = $lifecycle === "all" ? "findings" : `${$lifecycle} findings`;

  function sevClass(severity: string) {
    return severity === "Critical" ? "critical" : severity === "Warning" ? "warning" : "info";
  }
</script>

<h2>Findings</h2>
<div class="filters" role="group" aria-label="Lifecycle">
  {#each FILTERS as filter}
    <button aria-pressed={$lifecycle === filter.value} on:click={() => lifecycle.set(filter.value)}>{filter.label}</button>
  {/each}
</div>

{#if $q.isError}
  <p class="problem" role="alert">Unavailable: {($q.error as Error).message}</p>
{:else if $q.isLoading || !$q.data}
  <p class="muted">Loading…</p>
{:else if $q.data.length === 0}
  <p class="muted">No {noun}.</p>
{:else}
  <p class="muted">{findingsCount($q.data.length, LIMIT)} {noun}</p>
  <!-- Keyboard users need to focus this region to scroll a wide table. -->
  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
  <div class="table-scroll" role="region" aria-label="Findings table" tabindex="0">
    <table aria-label="Findings">
      <thead>
        <tr><th scope="col">Severity</th><th scope="col">State</th><th scope="col">Detector</th><th scope="col">Target</th><th scope="col">First seen</th><th scope="col">Last seen</th></tr>
      </thead>
      <tbody>
        {#each $q.data as finding (finding.id)}
          {@const target = finding.channel ?? finding.node ?? ""}
          {@const first = formatTime(finding.first_seen_at, now)}
          {@const last = formatTime(finding.last_seen_at, now)}
          {@const stale = staleNote(finding, last)}
          <tr>
            <td><span class="tag {sevClass(finding.severity)}">{finding.severity}</span></td>
            <td class="state"><span class="tag info">{finding.lifecycle}</span>{#if stale}{" "}<span class="tag stale">{stale.tag}</span>{/if}</td>
            <td><a href={findingHref(finding.id)}>{finding.detector}{#if target}<span class="visually-hidden"> on {target}</span>{/if}</a></td>
            <td class="mono">{target}</td>
            <td>{first.relative} <small class="muted">({first.absolute})</small></td>
            <td>{last.relative} <small class="muted">({last.absolute})</small></td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .filters { display: flex; gap: var(--space-2); margin-bottom: var(--space-3); }
  .filters button[aria-pressed="true"] { background: var(--surface-active); color: var(--text-on-active); }
  .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.8rem; overflow-wrap: anywhere; }
  td a { color: var(--accent); }
  .problem { color: var(--critical-text); }
</style>
