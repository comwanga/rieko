<script lang="ts">
  import type { Finding } from "./api";
  import { staleNote } from "./findings";
  import { findingsCount, formatTime } from "./overview";
  import { findingHref } from "./router";

  export let findings: Finding[] | undefined;
  export let loading: boolean;
  export let error: string | null;
  export let limit: number;
  export let now: Date;

  const severityClass = (severity: string) =>
    severity === "Critical" ? "critical" : severity === "Warning" ? "warning" : "info";
</script>

<section class="card" aria-labelledby="active-findings-title">
  <div class="head">
    <h3 id="active-findings-title">Active findings</h3>
    {#if findings && !error}<span class="count">{findingsCount(findings.length, limit)}<span class="visually-hidden">{" "}active findings</span></span>{/if}
    <a href="#/findings">View all findings</a>
  </div>

  {#if error}
    <p class="problem" role="alert">Unavailable: {error}</p>
  {:else if !findings}
    {#if loading}<p class="muted">Loading…</p>{/if}
  {:else if findings.length === 0}
    <p class="muted">No active findings.</p>
  {:else}
    <ul>
      {#each findings as finding (finding.id)}
        {@const first = formatTime(finding.first_seen_at, now)}
        {@const last = formatTime(finding.last_seen_at, now)}
        {@const stale = staleNote(finding, last)}
        <li>
          <div class="title">
            <span class="tag {severityClass(finding.severity)}">{finding.severity}</span>
            {#if stale}<span class="tag stale">{stale.tag}</span>{/if}
            <strong>{finding.detector}</strong>
            <span class="target">{finding.channel ?? finding.node ?? ""}</span>
          </div>
          {#if finding.explanation}
            <p><span class="muted">Explanation:</span> {finding.explanation}</p>
          {/if}
          <p class="muted">First seen {first.relative} <small>({first.absolute})</small>; last seen {last.relative} <small>({last.absolute})</small></p>
          <a class="details" href={findingHref(finding.id)}>View details<span class="visually-hidden"> for {finding.detector}{#if finding.channel ?? finding.node} on {finding.channel ?? finding.node}{/if}</span></a>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .head { align-items: center; display: flex; flex-wrap: wrap; gap: var(--space-2); }
  h3 { font-size: 1rem; margin: 0; }
  .head a { color: var(--accent); font-size: 0.85rem; margin-left: auto; }
  .count { background: var(--surface-input); border-radius: 999px; font-size: 0.8rem; padding: 0 var(--space-2); }
  ul { display: grid; gap: var(--space-2); list-style: none; margin: var(--space-3) 0 0; padding: 0; }
  li { border: 1px solid var(--border); border-radius: var(--radius); display: grid; gap: var(--space-1); padding: var(--space-3); }
  .title { align-items: center; display: flex; flex-wrap: wrap; gap: var(--space-2); }
  .target { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.8rem; overflow-wrap: anywhere; }
  p { font-size: 0.85rem; margin: 0; overflow-wrap: anywhere; }
  .details { color: var(--accent); font-size: 0.85rem; justify-self: start; }
  .problem { color: var(--critical-text); }
</style>
