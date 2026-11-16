<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, type Finding } from "./api";
  import { findingsCount } from "./overview";

  // Shares the Overview's active-findings query.
  const LIMIT = 50;
  const findings = createQuery({
    queryKey: ["findings", "active"],
    queryFn: () => get<Finding[]>(`/findings?lifecycle=active&limit=${LIMIT}`),
    refetchInterval: 15000,
  });
  // A failed refetch keeps earlier data; no count is shown rather than a stale one.
  $: count = $findings.data && !$findings.isError
    ? findingsCount($findings.data.length, LIMIT) : null;
</script>

{#if count}
  <!-- The visible number is decorative; the Findings link is described by the hidden text. -->
  <span class="nav-count" aria-hidden="true">{count}</span>
  <span id="findings-count" hidden>{count} active findings</span>
{/if}
