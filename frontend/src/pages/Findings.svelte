<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, type Finding } from "../lib/api";

  const q = createQuery({
    queryKey: ["findings"],
    queryFn: () => get<Finding[]>("/findings?limit=200"),
    refetchInterval: 15000,
  });

  function sevClass(s: string) {
    return s === "Critical" ? "critical" : s === "Warning" ? "warning" : "info";
  }

  function evMap(f: Finding) {
    return Object.fromEntries(f.evidence.map((e) => [e.key, String(e.value)]));
  }
</script>

<h2>Findings</h2>
{#if $q.isLoading}
  <p class="muted">Loading…</p>
{:else if $q.isError}
  <p class="critical">{(($q.error as Error)).message}</p>
{:else}
  <table>
    <thead>
      <tr><th>Severity</th><th>Detector</th><th>Channel</th><th>Ratio</th><th>Time</th></tr>
    </thead>
    <tbody>
      {#each $q.data ?? [] as f}
        {@const ev = evMap(f)}
        <tr>
          <td><span class="tag {sevClass(f.severity)}">{f.severity}</span></td>
          <td>{f.detector}</td>
          <td>{f.channel ?? f.node ?? "-"}</td>
          <td>{ev.local_ratio ?? "-"}</td>
          <td class="muted">{new Date(f.timestamp).toLocaleString()}</td>
        </tr>
        {#if f.explanation}
          <tr><td colspan="5" class="muted">{f.explanation}</td></tr>
        {/if}
      {/each}
    </tbody>
  </table>
{/if}