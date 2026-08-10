<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, post, type SimulationView, type SimulationComparison, type CompareSimulationsCommand } from "../lib/api";

  const simQ = createQuery<SimulationView[]>({
    queryKey: ["simulations"],
    queryFn: () => get<SimulationView[]>("/api/v2/simulations?limit=100"),
    refetchInterval: 15000,
  });

  let selectedId: string | null = null;
  let compareIds: string[] = [];
  let compareResult: SimulationComparison | null = null;
  let compareError = "";

  function select(id: string) {
    selectedId = selectedId === id ? null : id;
  }

  function toggleCompare(id: string) {
    if (compareIds.includes(id)) {
      compareIds = compareIds.filter(c => c !== id);
    } else if (compareIds.length < 2) {
      compareIds = [...compareIds, id];
    }
  }

  async function runComparison() {
    if (compareIds.length !== 2) return;
    compareError = "";
    compareResult = null;
    try {
      compareResult = await post<SimulationComparison>("/api/v2/simulations/compare", {
        left_simulation_id: compareIds[0],
        right_simulation_id: compareIds[1],
      } satisfies CompareSimulationsCommand);
    } catch (e) {
      compareError = (e as Error).message;
    }
  }
  function clearCompare() { compareIds = []; compareResult = null; compareError = ""; }

  function statusClass(s: string): string {
    if (s === "completed") return "info";
    if (s === "stale") return "warning";
    if (s === "failed" || s === "invalid_input") return "critical";
    return "warning";
  }
  function confidenceLabel(c: string): string {
    switch (c) {
      case "high": return "High — all inputs consistent";
      case "medium": return "Medium — partial data";
      case "low": return "Low — key assumptions needed";
      default: return "Unknown";
    }
  }
  function deltaText(delta: number): string {
    const sign = delta > 0 ? "+" : delta < 0 ? "\u2212" : "";
    return `${sign}${Math.abs(delta).toLocaleString()} msat`;
  }
  function pct(v: number): string { return `${Math.round(v * 100)}%`; }
  function dateFmt(ts: string): string { return new Date(ts).toLocaleString(); }

  $: selected = selectedId ? ($simQ.data ?? []).find(s => s.id === selectedId) : null;
</script>

<h2>Simulations</h2>
{#if $simQ.isLoading}
  <p class="muted">Loading…</p>
{:else if $simQ.isError}
  <p class="critical">{($simQ.error as Error).message}</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>Compare</th><th>Status</th><th>Action</th><th>Confidence</th>
        <th>Stale</th><th>Requested</th><th></th>
      </tr>
    </thead>
    <tbody>
      {#each $simQ.data ?? [] as s}
        <tr>
          <td>
            <input type="checkbox" checked={compareIds.includes(s.id)} on:change={() => toggleCompare(s.id)} disabled={s.status !== "completed"} aria-label="Select for comparison" />
          </td>
          <td><span class="tag {statusClass(s.status)}" role="status">{s.status}</span></td>
          <td>{s.action_type}</td>
          <td><span class="tag {s.confidence === 'high' ? 'info' : s.confidence === 'medium' ? 'info' : s.confidence === 'low' ? 'warning' : 'info'}">{s.confidence}</span></td>
          <td>{#if s.stale}<span class="tag critical" role="status">stale</span>{/if}</td>
          <td class="muted">{dateFmt(s.requested_at)}</td>
          <td><button on:click={() => select(s.id)}>{selectedId === s.id ? "hide" : "view"}</button></td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

{#if compareIds.length > 0}
  <div class="compare-bar" role="region" aria-label="Simulation comparison">
    <span>Comparing {compareIds.length}/2 selected</span>
    <button on:click={runComparison} disabled={compareIds.length !== 2}>Compare</button>
    <button class="btn-secondary" on:click={clearCompare}>Clear</button>
    {#if compareError}
      <p class="critical" role="alert">{compareError}</p>
    {/if}
  </div>
{/if}

{#if compareResult}
  <div class="card" style="margin-top:1rem" role="region" aria-label="Comparison result">
    <h3>Comparison</h3>
    <div class="grid">
      <div>
        <h4>{compareResult.left.id.slice(0, 8)}…</h4>
        <div class="kv"><span>Amount</span><span>{(compareResult.left.parameters.amount_msat / 1000).toLocaleString()} sats</span></div>
        <div class="kv"><span>Local ratio</span><span>{pct(compareResult.left.result?.projected.local_ratio ?? 0)}</span></div>
        <div class="kv"><span>Confidence</span><span>{compareResult.left.confidence}</span></div>
        <div class="kv"><span>Snapshot</span><span class="muted">{dateFmt(compareResult.left.source_observed_at)}</span></div>
        {#if compareResult.left.stale}<span class="tag critical" role="status">stale</span>{/if}
      </div>
      <div>
        <h4>{compareResult.right.id.slice(0, 8)}…</h4>
        <div class="kv"><span>Amount</span><span>{(compareResult.right.parameters.amount_msat / 1000).toLocaleString()} sats</span></div>
        <div class="kv"><span>Local ratio</span><span>{pct(compareResult.right.result?.projected.local_ratio ?? 0)}</span></div>
        <div class="kv"><span>Confidence</span><span>{compareResult.right.confidence}</span></div>
        <div class="kv"><span>Snapshot</span><span class="muted">{dateFmt(compareResult.right.source_observed_at)}</span></div>
        {#if compareResult.right.stale}<span class="tag critical" role="status">stale</span>{/if}
      </div>
    </div>
    <div class="kv" style="margin-top:0.75rem;font-weight:600">
      <span>Liquidity delta</span>
      <span>{deltaText(compareResult.projected_local_balance_delta_msat)}</span>
    </div>
    <p class="muted" style="margin-top:0.5rem" role="note">{compareResult.no_action_executed ? "No action was executed. These are deterministic projections based on recorded data." : ""}</p>
  </div>
{/if}

{#if selected}
  <div class="card" style="margin-top:1rem" role="region" aria-label="Simulation detail">
    <h3>Simulation {selected.id.slice(0, 8)}…</h3>

    <div class="grid">
      <div class="kv"><span>Status</span><span class="tag {statusClass(selected.status)}" role="status">{selected.status}</span></div>
      <div class="kv"><span>Model</span><span>{selected.model_id} v{selected.model_version}</span></div>
      <div class="kv"><span>Confidence</span><span title={confidenceLabel(selected.confidence)}>{selected.confidence}</span></div>
      <div class="kv"><span>Observed</span><span class="muted">{dateFmt(selected.source_observed_at)}</span></div>
    </div>

    <div class="grid" style="margin-top:0.75rem">
      <div class="kv"><span>Source channel</span><span>{selected.parameters.source_channel}</span></div>
      <div class="kv"><span>Destination</span><span>{selected.parameters.destination_channel}</span></div>
      <div class="kv"><span>Amount</span><span>{(selected.parameters.amount_msat / 1000).toLocaleString()} sats</span></div>
      {#if selected.stale}
        <div class="kv"><span></span><span class="tag critical" role="status">Source data is stale</span></div>
      {/if}
    </div>

    {#if selected.result}
      <div class="grid" style="margin-top:1rem">
        <div class="card">
          <h4>Baseline</h4>
          <div class="kv"><span>Local ratio</span><span>{pct(selected.result.baseline.local_ratio)}</span></div>
          <div class="kv"><span>Local balance</span><span>{(selected.result.baseline.local_balance_msat / 1e6).toFixed(2)}M msat</span></div>
          <div class="kv"><span>Capacity</span><span>{(selected.result.baseline.capacity_msat / 1e6).toFixed(2)}M msat</span></div>
        </div>
        <div class="card">
          <h4>Projection</h4>
          <div class="kv"><span>Local ratio</span><span>{pct(selected.result.projected.local_ratio)}</span></div>
          <div class="kv"><span>Local balance</span><span>{(selected.result.projected.local_balance_msat / 1e6).toFixed(2)}M msat</span></div>
          <div class="kv"><span>Capacity</span><span>{(selected.result.projected.capacity_msat / 1e6).toFixed(2)}M msat</span></div>
        </div>
      </div>

      {#if selected.result.deltas.length > 0}
        <h4 style="margin-top:1rem">Deltas</h4>
        <table>
          <thead>
            <tr><th scope="col">Channel</th><th scope="col">Local before</th><th scope="col">Local after</th><th scope="col">Delta</th><th scope="col">Clears finding</th></tr>
          </thead>
          <tbody>
            {#each selected.result.deltas as d}
              <tr>
                <td>{d.channel_id.slice(0, 8)}…</td>
                <td>{(d.local_before_msat / 1e6).toFixed(2)}M msat</td>
                <td>{(d.local_after_msat / 1e6).toFixed(2)}M msat</td>
                <td>{deltaText(d.delta_msat)}</td>
                <td>{#if d.clears_finding}<span class="tag info">yes</span>{:else}<span class="tag warning">no</span>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}

      {#if selected.result.assumptions.length > 0}
        <h4 style="margin-top:1rem">Assumptions</h4>
        {#each selected.result.assumptions as a}
          <div class="kv">
            <span><span class="tag {a.severity === 'critical' ? 'critical' : a.severity === 'warning' ? 'warning' : 'info'}" role="note">{a.severity}</span> <code>{a.code}</code></span>
            <span>{a.description}</span>
          </div>
        {/each}
      {/if}

      {#if selected.result.warnings.length > 0}
        <h4 style="margin-top:1rem">Warnings</h4>
        {#each selected.result.warnings as w}
          <div class="kv">
            <span><span class="tag {w.severity === 'critical' ? 'critical' : w.severity === 'warning' ? 'warning' : 'info'}" role="note">{w.severity}</span> <code>{w.code}</code></span>
            <span>{w.description}</span>
          </div>
        {/each}
      {/if}
    {/if}

    {#if selected.error_code}
      <div class="kv" style="margin-top:0.5rem"><span>Error</span><span class="tag critical" role="status">{selected.error_code}</span></div>
    {/if}

    <p class="muted" style="margin-top:1rem;padding:0.5rem;background:#f8f9fa;border-radius:6px" role="note">
      This is a deterministic projection based on recorded data. Rieko did not execute any action, and the Lightning Network may behave differently.
    </p>
  </div>
{/if}

<style>
.compare-bar {
  display: flex; align-items: center; gap: 0.75rem;
  margin-top: 1rem; padding: 0.6rem 0.75rem;
  background: #f8f9fa; border-radius: 8px; font-size: 0.85rem;
}
.btn-secondary { background: #f0f1f4; color: #1a1a2e; border: 1px solid #d0d3db; }
</style>
