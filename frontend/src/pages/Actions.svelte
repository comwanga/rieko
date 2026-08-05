<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, type Recommendation } from "../lib/api";

  const q = createQuery({
    queryKey: ["recommendations"],
    queryFn: () => get<Recommendation[]>("/recommendations?limit=200"),
    refetchInterval: 15000,
  });

  function stageClass(s: string) {
    switch (s) {
      case "Executed":
        return "info";
      case "Approved":
        return "warning";
      case "Rejected":
        return "critical";
      default:
        return "info";
    }
  }
</script>

<h2>Actions</h2>
{#if $q.isLoading}
  <p class="muted">Loading…</p>
{:else if $q.isError}
  <p class="critical">{(($q.error as Error)).message}</p>
{:else}
  <table>
    <thead>
      <tr><th>Type</th><th>Stage</th><th>Target</th><th>Summary</th></tr>
    </thead>
    <tbody>
      {#each $q.data ?? [] as r}
        <tr>
          <td>{r.action.action_type}</td>
          <td><span class="tag {stageClass(r.action.stage)}">{r.action.stage}</span></td>
          <td>{r.action.target ?? "-"}</td>
          <td class="muted">{r.action.summary}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}