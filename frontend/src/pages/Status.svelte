<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, type Status } from "../lib/api";

  const q = createQuery<Status>({
    queryKey: ["status"],
    queryFn: () => get<Status>("/status"),
    refetchInterval: 15000,
  });

  function healthClass(status: string) {
    return status === "healthy" || status === "ok"
      ? "info"
      : status === "degraded" || status === "not_initialized"
        ? "warning"
        : "critical";
  }
</script>

<h2>Overview</h2>
{#if $q.isLoading}
  <p class="muted">Loading…</p>
{:else if $q.isError}
  <p class="critical">{(($q.error as Error)).message}</p>
{:else if $q.data}
  {@const status = $q.data}
  {@const counts = status.counts}
  <p class="muted">
    {status.engine} v{status.version} · schema {status.schema_version} ·
    {status.read_only ? "node read-only" : "node mutation capable"}
  </p>
  <div class="grid">
    <div class="card">
      <div class="kv"><span>Overall</span><span class="tag {healthClass(status.overall)}">{status.overall}</span></div>
      <div class="kv"><span>Database integrity</span><span class="tag {healthClass(status.integrity)}">{status.integrity}</span></div>
      <div class="kv"><span>Source</span><span>{status.source ?? "not configured"}</span></div>
    </div>
    <div class="card">
      <div class="kv"><span>Findings</span><span>{counts.findings}</span></div>
      <div class="kv"><span>Recommendations</span><span>{counts.recommendations}</span></div>
      <div class="kv"><span>Simulations</span><span>{counts.simulations}</span></div>
    </div>
    <div class="card">
      <div class="kv"><span>Snapshot rows</span><span>{counts.channel_snapshots}</span></div>
      <div class="kv"><span>Audit entries</span><span>{counts.audit}</span></div>
      <div class="kv"><span>LLM</span><span>{status.llm}</span></div>
      <div class="kv"><span>Alerts</span><span>{status.alert_sink}</span></div>
      <div class="kv"><span>Cleanup</span><span>{status.cleanup}</span></div>
    </div>
  </div>
{:else}
  <p class="muted">Status unavailable.</p>
{/if}
