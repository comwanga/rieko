<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, type Status } from "./api";
  import { pipelineBadge } from "./overview";

  // Shares the Overview's status query. `overall` describes Rieko's own
  // pipeline; it does not yet cover Bitcoin Core or LND (finding M1), so the
  // pill names the pipeline and never claims that all systems are working.
  const status = createQuery({
    queryKey: ["status"],
    queryFn: () => get<Status>("/status"),
    refetchInterval: 15000,
  });
</script>

<!-- The error case comes first: after a failed refetch the query keeps its
     earlier data, which must not be shown as the current state. -->
{#if $status.isError}
  <a class="pill badge neutral" href="#/overview">Rieko pipeline: unavailable</a>
{:else if $status.data}
  {@const badge = pipelineBadge($status.data.overall)}
  <a class="pill badge {badge.kind}" href="#/overview">Rieko pipeline: {badge.label}</a>
{/if}

<style>
  .pill { font-size: 0.8rem; margin-right: auto; text-decoration: none; }
</style>
