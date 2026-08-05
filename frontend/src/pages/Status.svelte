<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, type Status } from "../lib/api";

  const q = createQuery<Status>({
    queryKey: ["status"],
    queryFn: () => get<Status>("/status"),
    refetchInterval: 15000,
  });

  function sevClass(s: string) {
    return s === "Critical" ? "critical" : s === "Warning" ? "warning" : "info";
  }

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

<h2>Overview</h2>
{#if $q.isLoading}
  <p class="muted">Loading…</p>
{:else if $q.isError}
  <p class="critical">{(($q.error as Error)).message}</p>
{:else}
  {@const counts = $q.data.counts}
  <p class="muted">
    {$q.data.engine} v{$q.data.version} · {$q.data.read_only ? "read-only" : "read-write"}
  </p>
  <div class="grid">
    <div class="card">
      <div class="kv"><span>Findings</span><span>{counts.findings}</span></div>
      {#each Object.entries(counts.findings_by_severity) as [sev, n]}
        <div class="kv">
          <span class="tag {sevClass(sev)}">{sev}</span>
          <span>{n}</span>
        </div>
      {/each}
    </div>
    <div class="card">
      <div class="kv"><span>Actions</span><span>{counts.recommendations}</span></div>
      {#each Object.entries(counts.recommendations_by_stage) as [stage, n]}
        <div class="kv">
          <span class="tag {stageClass(stage)}">{stage}</span>
          <span>{n}</span>
        </div>
      {/each}
    </div>
    <div class="card">
      <div class="kv"><span>Simulations</span><span>{counts.simulations}</span></div>
      <div class="kv"><span>Channels tracked</span><span>{counts.channel_snapshots}</span></div>
      <div class="kv"><span>Audit entries</span><span>{counts.audit}</span></div>
    </div>
  </div>
{/if}