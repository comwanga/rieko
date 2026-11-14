<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get, type Finding, type Status } from "../lib/api";
  import ActiveFindings from "../lib/ActiveFindings.svelte";
  import ServiceCard from "../lib/ServiceCard.svelte";
  import {
    btcpayCard, coreCard, findingsCount, lightningCard, riekoCard,
    type BitcoinInspection, type BtcPayInspection, type LightningInspection,
  } from "../lib/overview";

  const FINDINGS_LIMIT = 50;
  const poll = { refetchInterval: 15000 };

  const status = createQuery({ queryKey: ["status"], queryFn: () => get<Status>("/status"), ...poll });
  const bitcoin = createQuery({ queryKey: ["inspect", "bitcoin"], queryFn: () => get<BitcoinInspection>("/inspect/bitcoin"), ...poll });
  const lightning = createQuery({ queryKey: ["inspect", "lightning"], queryFn: () => get<LightningInspection>("/inspect/lightning"), ...poll });
  const btcpay = createQuery({ queryKey: ["inspect", "btcpay"], queryFn: () => get<BtcPayInspection>("/inspect/btcpay"), ...poll });
  const findings = createQuery({
    queryKey: ["findings", "active"],
    queryFn: () => get<Finding[]>(`/findings?lifecycle=active&limit=${FINDINGS_LIMIT}`),
    ...poll,
  });

  const errorOf = (query: { isError: boolean; error: unknown }) =>
    query.isError ? (query.error as Error).message : null;
  // Relative times are recomputed whenever any response arrives.
  const stamp = (..._updates: number[]) => new Date();
  $: now = stamp($status.dataUpdatedAt, $bitcoin.dataUpdatedAt, $lightning.dataUpdatedAt, $btcpay.dataUpdatedAt, $findings.dataUpdatedAt);
  // A failed refetch keeps earlier data; the count is omitted rather than shown as current.
  $: activeCount = $findings.data && !$findings.isError ? findingsCount($findings.data.length, FINDINGS_LIMIT) : null;
</script>

<h2>Overview</h2>
<p class="muted intro">State as last observed by this Rieko agent. Relative times use this device's clock.</p>

<div class="services" role="region" aria-label="System health">
  <ServiceCard title="Bitcoin Core" icon="blocks" model={$bitcoin.data && coreCard($bitcoin.data, now)}
    loading={$bitcoin.isLoading} error={errorOf($bitcoin)} />
  <ServiceCard title="LND" icon="bolt" model={$lightning.data && lightningCard($lightning.data, now)}
    loading={$lightning.isLoading} error={errorOf($lightning)} />
  <ServiceCard title="BTCPay Server" icon="store" model={$btcpay.data && btcpayCard($btcpay.data, now)}
    loading={$btcpay.isLoading} error={errorOf($btcpay)} />
  <ServiceCard title="Rieko" icon="database" model={$status.data && riekoCard($status.data, activeCount, now)}
    loading={$status.isLoading} error={errorOf($status)} />
</div>

<ActiveFindings findings={$findings.data} loading={$findings.isLoading} error={errorOf($findings)}
  limit={FINDINGS_LIMIT} {now} />

<style>
  .intro { margin: -0.5rem 0 var(--space-4); }
  .services {
    display: grid;
    gap: var(--space-3);
    grid-template-columns: repeat(auto-fit, minmax(min(240px, 100%), 1fr));
    margin-bottom: var(--space-4);
  }
</style>
