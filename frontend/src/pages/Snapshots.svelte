<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, type ChannelSnapshot } from "../lib/api";

  const q = createQuery({
    queryKey: ["snapshots"],
    queryFn: () => get<ChannelSnapshot[]>("/snapshots?limit=500"),
    refetchInterval: 15000,
  });

  // Latest snapshot per network/node/channel identity, plus a small history toggle.
  let selected: string | null = null;

  $: latest = (() => {
    const byChannel = new Map<string, ChannelSnapshot[]>();
    for (const s of $q.data ?? []) {
      const key = `${s.network ?? "legacy"}\u0000${s.node_id ?? "unknown"}\u0000${s.channel_id}`;
      const list = byChannel.get(key) ?? [];
      list.push(s);
      byChannel.set(key, list);
    }
    return Array.from(byChannel.entries())
      .map(([key, list]) => ({ key, snaps: list.sort((a, b) => b.ts.localeCompare(a.ts)) }))
      .sort((a, b) => a.key.localeCompare(b.key));
  })();

  function pct(v: number | undefined) {
    return v === undefined ? "-" : `${Math.round(v * 100)}%`;
  }
</script>

<h2>Channel liquidity</h2>
{#if $q.isLoading}
  <p class="muted">Loading…</p>
{:else if $q.isError}
  <p class="critical">{(($q.error as Error)).message}</p>
{:else}
  <table>
    <thead>
       <tr><th>Network</th><th>Node</th><th>Channel</th><th>Status</th><th>Local</th><th>Capacity</th><th></th></tr>
    </thead>
    <tbody>
      {#each latest as { key, snaps }}
        {@const s = snaps[0]}
        <tr>
          <td>{s.network ?? "legacy"}</td>
          <td class="muted">{s.node_id ?? "unknown"}</td>
          <td>{s.channel_id}</td>
          <td>{s.status}</td>
          <td>{pct(s.local_ratio)}</td>
          <td class="muted">{(s.capacity_msat / 1e6).toFixed(0)}M msat</td>
          <td>
            <button on:click={() => (selected = selected === key ? null : key)}>
              {selected === key ? "hide" : "history"}
            </button>
          </td>
        </tr>
        {#if selected === key}
          <tr>
            <td colspan="7">
              <div class="grid">
                {#each snaps as h}
                  <div class="card">
                    <div class="kv"><span>Local</span><span>{pct(h.local_ratio)}</span></div>
                    <div class="kv"><span>When</span><span class="muted">{new Date(h.ts).toLocaleString()}</span></div>
                  </div>
                {/each}
              </div>
            </td>
          </tr>
        {/if}
      {/each}
    </tbody>
  </table>
{/if}
