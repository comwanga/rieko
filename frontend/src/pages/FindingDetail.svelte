<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, type Finding } from "../lib/api";
  import { AuthenticationError } from "../lib/auth";
  import {
    actionabilityLabel, describeProvenance, evidenceValue, recommendationsFor, type RecommendationDetail,
  } from "../lib/findings";
  import { formatTime } from "../lib/overview";
  import { routeHref } from "../lib/router";

  export let id: string;
  const RECOMMENDATION_LIMIT = 500;

  const notFound = (error: unknown) => error instanceof Error && error.message.startsWith("404 ");
  const finding = createQuery({
    queryKey: ["findings", "detail", id],
    queryFn: () => get<Finding>(`/findings/${encodeURIComponent(id)}`),
    // A missing finding will not appear on retry; authentication keeps its own handling.
    retry: (failures, error) => !(error instanceof AuthenticationError) && !notFound(error) && failures < 3,
    refetchInterval: 15000,
  });
  const recommendations = createQuery({
    queryKey: ["recommendations", "all", RECOMMENDATION_LIMIT],
    queryFn: () => get<RecommendationDetail[]>(`/recommendations?lifecycle=all&limit=${RECOMMENDATION_LIMIT}`),
    refetchInterval: 15000,
  });

  const stamp = (..._updates: number[]) => new Date();
  $: now = stamp($finding.dataUpdatedAt, $recommendations.dataUpdatedAt);
  // A failed refetch keeps earlier data; it is not shown as current.
  $: current = $finding.isError ? undefined : $finding.data;
  $: provenance = current ? describeProvenance(current.provenance) : null;
  $: linked = current && $recommendations.data && !$recommendations.isError
    ? recommendationsFor($recommendations.data, current.id, RECOMMENDATION_LIMIT) : null;
  const time = (iso: string, at: Date) => {
    const value = formatTime(iso, at);
    return `${value.relative} (${value.absolute})`;
  };
  const sevClass = (severity: string) => severity === "Critical" ? "critical" : severity === "Warning" ? "warning" : "info";
</script>

<p class="back"><a href={routeHref("findings")}>Back to findings</a></p>
<h2>Finding{#if current}: {current.detector}{/if}</h2>

{#if $finding.isError}
  {#if notFound($finding.error)}
    <p class="muted">Finding not found.</p>
  {:else}
    <p class="problem" role="alert">Unavailable: {($finding.error as Error).message}</p>
  {/if}
{:else if !current}
  <p class="muted">Loading…</p>
{:else}
  <section class="card" aria-labelledby="finding-summary">
    <h3 id="finding-summary">Summary</h3>
    <dl>
      <div><dt>Severity</dt><dd><span class="tag {sevClass(current.severity)}">{current.severity}</span></dd></div>
      <div><dt>State</dt><dd>{current.lifecycle}</dd></div>
      <div><dt>Detector</dt><dd>{current.detector} v{current.detector_version}</dd></div>
      {#if current.node}<div><dt>Node</dt><dd class="mono">{current.node}</dd></div>{/if}
      {#if current.channel}<div><dt>Channel</dt><dd class="mono">{current.channel}</dd></div>{/if}
      <div><dt>First seen</dt><dd>{time(current.first_seen_at, now)}</dd></div>
      <div><dt>Last seen</dt><dd>{time(current.last_seen_at, now)}</dd></div>
    </dl>
  </section>

  {#if current.explanation}
    <section class="card" aria-labelledby="finding-explanation">
      <h3 id="finding-explanation">Explanation</h3>
      <p>{current.explanation}</p>
    </section>
  {/if}

  <section class="card" aria-labelledby="finding-evidence">
    <h3 id="finding-evidence">Evidence</h3>
    {#if current.evidence.length === 0}
      <p class="muted">No evidence is recorded for this finding.</p>
    {:else}
      <dl>
        {#each current.evidence as item}
          {@const value = evidenceValue(item.value)}
          <div><dt>{item.key}</dt><dd>{#if value.block}<pre class="json">{value.text}</pre>{:else}{value.text}{/if}</dd></div>
        {/each}
      </dl>
    {/if}
  </section>

  <section class="card" aria-labelledby="finding-provenance">
    <h3 id="finding-provenance">Provenance</h3>
    {#if !provenance}
      <p class="muted">No provenance is recorded for this finding.</p>
    {:else}
      <dl>
        {#if provenance.network}<div><dt>Network</dt><dd>{provenance.network}</dd></div>{/if}
        {#each provenance.source as row}<div><dt>{row.label}</dt><dd class="mono">{row.value}</dd></div>{/each}
        <div><dt>Observation</dt><dd>{provenance.observation.kind}</dd></div>
        {#if provenance.observation.channel}<div><dt>Observed channel</dt><dd class="mono">{provenance.observation.channel}</dd></div>{/if}
      </dl>
      {#if provenance.observation.snapshots.length}
        <h4>Referenced snapshots</h4>
        <ul class="snapshots">
          {#each provenance.observation.snapshots as snapshot}
            <li>{time(snapshot.observed_at, now)} <span class="mono">{snapshot.state_digest}</span></li>
          {/each}
        </ul>
      {/if}
      {#if provenance.producers.length}
        <!-- Keyboard users need to focus this region to scroll a wide table. -->
        <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
        <div class="table-scroll" role="region" aria-label="Producers table" tabindex="0">
          <table aria-label="Producers">
            <thead><tr><th scope="col">Producer</th><th scope="col">Version</th><th scope="col">Role</th></tr></thead>
            <tbody>
              {#each provenance.producers as producer}
                <tr><td>{producer.name}</td><td>{producer.version}</td><td>{producer.role}</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {/if}
  </section>

  <section class="card" aria-labelledby="finding-recommendations">
    <h3 id="finding-recommendations">Recommendations</h3>
    {#if $recommendations.isError}
      <p class="problem" role="alert">Unavailable: {($recommendations.error as Error).message}</p>
    {:else if !linked}
      <p class="muted">Loading…</p>
    {:else if linked.items.length === 0}
      <p class="muted">No recommendations are linked to this finding.</p>
    {:else}
      <ul class="recommendations">
        {#each linked.items as rec (rec.action.id)}
          <li>
            <h4>{rec.action.summary}</h4>
            <dl>
              <div><dt>Action</dt><dd>{rec.action.action_type}</dd></div>
              <div><dt>Stage</dt><dd>{rec.action.stage}</dd></div>
              <div><dt>State</dt><dd>{rec.lifecycle ?? "active"}</dd></div>
              <div><dt>Actionability</dt><dd>{actionabilityLabel(rec.rationale.actionability)}</dd></div>
            </dl>
            <p><span class="muted">Expected effect:</span> {rec.rationale.expected_effect}</p>
            {#each [["Based on evidence", rec.rationale.evidence], ["Preconditions", rec.rationale.preconditions], ["Risks", rec.rationale.risks], ["Limitations", rec.rationale.limitations]] as [label, entries]}
              {#if entries.length}
                <p class="muted">{label}</p>
                <ul>{#each entries as entry}<li>{entry}</li>{/each}</ul>
              {/if}
            {/each}
          </li>
        {/each}
      </ul>
    {/if}
    {#if linked?.possiblyIncomplete}
      <p class="muted">Only the latest {RECOMMENDATION_LIMIT} recommendations were checked, so this list may be incomplete.</p>
    {/if}
  </section>
{/if}

<style>
  .back { margin: 0 0 var(--space-2); }
  .back a { color: var(--accent); }
  section { margin-bottom: var(--space-3); min-width: 0; }
  h3 { font-size: 1rem; margin: 0 0 var(--space-2); }
  h4 { font-size: 0.9rem; margin: var(--space-2) 0 var(--space-1); }
  dl { display: grid; gap: var(--space-1); margin: 0; }
  dl div { display: grid; font-size: 0.85rem; gap: var(--space-3); grid-template-columns: minmax(8rem, 14rem) minmax(0, 1fr); }
  dt { color: var(--text-muted); overflow-wrap: anywhere; }
  dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
  p { font-size: 0.85rem; margin: var(--space-1) 0; overflow-wrap: anywhere; }
  .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.8rem; }
  .snapshots, .recommendations { display: grid; gap: var(--space-2); list-style: none; margin: 0 0 var(--space-2); padding: 0; }
  .snapshots li { font-size: 0.85rem; overflow-wrap: anywhere; }
  .recommendations > li { border: 1px solid var(--border); border-radius: var(--radius); min-width: 0; overflow-wrap: anywhere; padding: var(--space-3); }
  .recommendations ul { font-size: 0.85rem; margin: 0; padding-left: var(--space-5); }
  .problem { color: var(--critical-text); }
  @media (max-width: 600px) {
    dl div { gap: 0; grid-template-columns: minmax(0, 1fr); }
  }
</style>
