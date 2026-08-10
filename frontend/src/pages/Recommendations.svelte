<script lang="ts">
  import { createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { get, post, type Recommendation, type Finding, type ChannelSnapshot, type CreateSimulationOutcome } from "../lib/api";

  const recQ = createQuery<Recommendation[]>({
    queryKey: ["recommendations"],
    queryFn: () => get<Recommendation[]>("/recommendations?limit=100"),
    refetchInterval: 15000,
  });

  const findingQ = createQuery<Finding[]>({
    queryKey: ["findings", "all"],
    queryFn: () => get<Finding[]>("/findings?limit=200&lifecycle=all"),
    refetchInterval: 15000,
  });

  const snapQ = createQuery<ChannelSnapshot[]>({
    queryKey: ["snapshots"],
    queryFn: () => get<ChannelSnapshot[]>("/snapshots?limit=500"),
    refetchInterval: 15000,
  });

  const queryClient = useQueryClient();

  let selectedRec: Recommendation | null = null;
  let formSource = "";
  let formDest = "";
  let formAmount = "";
  let formStale = false;
  let formError = "";
  let formSubmitting = false;

  function openSim(rec: Recommendation) {
    selectedRec = rec;
    formSource = "";
    formDest = "";
    formAmount = "";
    formStale = false;
    formError = "";
  }
  function closeSim() { selectedRec = null; }

  function distinctChannels(): string[] {
    const latest = new Map<string, ChannelSnapshot>();
    for (const s of $snapQ.data ?? []) {
      const key = `${s.network ?? "legacy"}\x00${s.node_id ?? "unknown"}\x00${s.channel_id}`;
      const cur = latest.get(key);
      if (!cur || s.ts > cur.ts) latest.set(key, s);
    }
    return Array.from(latest.values()).map(s => s.channel_id).filter((v, i, a) => a.indexOf(v) === i).sort();
  }

  function channelLabel(id: string): string {
    const snap = ($snapQ.data ?? []).find(s => s.channel_id === id);
    if (!snap) return id;
    const pct = snap.local_ratio === undefined ? "?" : `${Math.round(snap.local_ratio * 100)}%`;
    const cap = `${(snap.capacity_msat / 1e6).toFixed(1)}M`;
    return `${id} (${pct} \xb7 ${cap})`;
  }

  async function submitSim() {
    formError = "";
    const amt = Number(formAmount);
    if (!Number.isFinite(amt) || amt <= 0 || !Number.isInteger(amt)) {
      formError = "Amount must be a positive whole number of sats.";
      return;
    }
    if (!formSource || !formDest) {
      formError = "Both source and destination channels are required.";
      return;
    }
    if (formSource === formDest) {
      formError = "Source and destination must be different channels.";
      return;
    }
    if (!selectedRec) return;
    formSubmitting = true;
    try {
      await post<CreateSimulationOutcome>("/api/v2/simulations", {
        recommendation_id: selectedRec.action.id,
        model_id: "liquidity-redistribution",
        source_channel: formSource,
        destination_channel: formDest,
        amount_sats: amt,
        allow_stale: formStale,
      });
      queryClient.invalidateQueries({ queryKey: ["simulations"] });
      closeSim();
    } catch (e) {
      formError = (e as Error).message;
    } finally {
      formSubmitting = false;
    }
  }

  function findingFor(rec: Recommendation): Finding | undefined {
    return ($findingQ.data ?? []).find(f => f.id === rec.finding_id);
  }

  function severityClass(s: string) {
    return s === "Critical" ? "critical" : s === "Warning" ? "warning" : "info";
  }

  $: channels = distinctChannels();
</script>

<h2>Recommendations</h2>
{#if $recQ.isLoading}
  <p class="muted">Loading…</p>
{:else if $recQ.isError}
  <p class="critical">{($recQ.error as Error).message}</p>
{:else}
  <table>
    <thead>
      <tr><th>Finding</th><th>Detection</th><th>Action</th><th>State</th><th></th></tr>
    </thead>
    <tbody>
      {#each $recQ.data ?? [] as rec}
        {@const fnd = findingFor(rec)}
        <tr>
          <td>
            {#if fnd}
              <span class="tag {severityClass(fnd.severity)}">{fnd.severity}</span>
              {" "}{fnd.detector}
            {:else}
              <span class="muted">{rec.finding_id.slice(0, 8)}…</span>
            {/if}
          </td>
          <td class="muted">{fnd?.evidence?.map(e => e.key)?.join(", ") ?? ""}</td>
          <td>{rec.action.summary}</td>
          <td><span class="tag info">{rec.action.stage}</span></td>
          <td>
            <button on:click={() => openSim(rec)}>Simulate</button>
          </td>
        </tr>
        {#if fnd?.explanation}
          <tr>
            <td colspan="5" class="muted" style="padding-top:0">{fnd.explanation}</td>
          </tr>
        {/if}
      {/each}
    </tbody>
  </table>
{/if}

{#if selectedRec}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="overlay" role="dialog" aria-label="Create simulation" tabindex="0" on:keydown={(e) => e.key === 'Escape' && closeSim()}>
    <div class="overlay-card">
      <h3>Simulate: {selectedRec.action.summary}</h3>
      {#if findingFor(selectedRec)}
        {@const fnd = findingFor(selectedRec)}
        {#if fnd}
          <div class="kv"><span>Finding</span><span><span class="tag {severityClass(fnd.severity)}">{fnd.severity}</span> {fnd.detector} &mdash; {fnd.channel ?? fnd.node ?? "(node)"}</span></div>
          {#if fnd.explanation}
            <div class="kv"><span>Context</span><span class="muted">{fnd.explanation}</span></div>
          {/if}
        {/if}
      {/if}
      <div class="kv"><span>Model</span><span>liquidity-redistribution (v3)</span></div>
      <div class="kv"><span>Snapshot freshness</span><span class="muted">Latest available (real-time observation)</span></div>

      <div class="form-group">
        <label for="sim-source">Source channel <span class="muted">(provides liquidity)</span></label>
        <select id="sim-source" bind:value={formSource} aria-label="Source channel">
          <option value="">-- select --</option>
          {#each channels as ch}
            <option value={ch}>{channelLabel(ch)}</option>
          {/each}
        </select>
      </div>
      <div class="form-group">
        <label for="sim-dest">Destination channel <span class="muted">(receives liquidity)</span></label>
        <select id="sim-dest" bind:value={formDest} aria-label="Destination channel">
          <option value="">-- select --</option>
          {#each channels as ch}
            <option value={ch}>{channelLabel(ch)}</option>
          {/each}
        </select>
      </div>
      <div class="form-group">
        <label for="sim-amount">Amount <span class="muted">(sats)</span></label>
        <input id="sim-amount" type="number" bind:value={formAmount} placeholder="50000" min="1" step="1" aria-label="Amount in sats" />
      </div>
      <div class="form-group">
        <span class="muted" role="note">Routing fees are not estimated; actual cost may vary.</span>
      </div>
      <div class="form-group">
        <label>
          <input type="checkbox" bind:checked={formStale} />
          Allow stale snapshots
        </label>
      </div>
      {#if formError}
        <p class="critical" role="alert">{formError}</p>
      {/if}
      <div class="form-actions">
        <button on:click={submitSim} disabled={formSubmitting}>
          {formSubmitting ? "Submitting…" : "Run simulation"}
        </button>
        <button class="btn-secondary" on:click={closeSim}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
.overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.35);
  display: flex; align-items: center; justify-content: center;
  z-index: 10;
}
.overlay-card {
  background: #fff; border-radius: 8px; padding: 1.5rem;
  max-width: 520px; width: 90%; max-height: 90vh; overflow-y: auto;
}
.form-group { margin: 0.75rem 0; }
.form-group label { display: block; font-size: 0.85rem; margin-bottom: 0.25rem; }
select, input[type="number"] {
  width: 100%; padding: 0.4rem 0.5rem; border: 1px solid #e2e4ea; border-radius: 6px;
  font-size: 0.85rem;
}
.form-actions { display: flex; gap: 0.5rem; margin-top: 1rem; }
.btn-secondary { background: #f0f1f4; color: #1a1a2e; border: 1px solid #d0d3db; }
</style>
