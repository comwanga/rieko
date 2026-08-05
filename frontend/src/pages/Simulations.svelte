<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, type Simulation } from "../lib/api";

  const q = createQuery({
    queryKey: ["simulations"],
    queryFn: () => get<Simulation[]>("/simulations?limit=200"),
    refetchInterval: 15000,
  });

  function pct(v: number) {
    return `${Math.round(v * 100)}%`;
  }
</script>

<h2>Simulations</h2>
{#if $q.isLoading}
  <p class="muted">Loading…</p>
{:else if $q.isError}
  <p class="critical">{(($q.error as Error)).message}</p>
{:else}
  <table>
    <thead>
      <tr><th>Action</th><th>Before</th><th>After</th><th>Delta (msat)</th><th>Clears</th><th>Summary</th></tr>
    </thead>
    <tbody>
      {#each $q.data ?? [] as s}
        <tr>
          <td>{s.action_type}</td>
          <td>{pct(s.projection.local_ratio_before)}</td>
          <td>{pct(s.projection.local_ratio_after)}</td>
          <td>{s.projection.delta_msat}</td>
          <td>{s.projection.clears_finding ? "yes" : "no"}</td>
          <td class="muted">{s.projection.summary}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}