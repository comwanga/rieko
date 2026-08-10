<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, type AuditEntry } from "../lib/api";

  const q = createQuery<AuditEntry[]>({
    queryKey: ["audit"],
    queryFn: () => get<AuditEntry[]>("/audit?limit=200"),
    refetchInterval: 15000,
  });

  function stageClass(s: string) {
    switch (s) {
      case "Executed":
        return "info";
      case "Approved":
        return "warning";
      case "Rejected":
      case "Failed":
        return "critical";
      default:
        return "info";
    }
  }

  function detailsText(d: unknown) {
    if (typeof d === "object" && d !== null) {
      const finding = (d as Record<string, unknown>).finding_id;
      return typeof finding === "string" ? `finding ${finding.slice(0, 8)}…` : "";
    }
    return "";
  }
</script>

<h2>Audit log</h2>
{#if $q.isLoading}
  <p class="muted">Loading…</p>
{:else if $q.isError}
  <p class="critical">{(($q.error as Error)).message}</p>
{:else}
  <table>
    <thead>
      <tr><th scope="col">Stage</th><th scope="col">Type</th><th scope="col">Action</th><th scope="col">Actor</th><th scope="col">Details</th><th scope="col">Time</th></tr>
    </thead>
    <tbody>
      {#each $q.data ?? [] as e}
        <tr>
          <td><span class="tag {stageClass(e.stage)}">{e.stage}</span></td>
          <td>{e.action_type}</td>
          <td class="muted">{e.action_id.slice(0, 8)}…</td>
          <td>{e.actor}</td>
          <td class="muted">{detailsText(e.details)}</td>
          <td class="muted">{new Date(e.timestamp).toLocaleString()}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}
