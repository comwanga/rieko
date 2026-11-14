<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { get } from "../lib/api";
  import ServiceCard from "../lib/ServiceCard.svelte";
  import {
    btcpayCard, coreCard, lightningCard,
    type BitcoinInspection, type BtcPayInspection, type LightningInspection,
  } from "../lib/overview";
  import Snapshots from "./Snapshots.svelte";

  // Same queries and mapping as the Overview cards; per-service detail grows in MS-3.6.
  const poll = { refetchInterval: 15000 };
  const bitcoin = createQuery({ queryKey: ["inspect", "bitcoin"], queryFn: () => get<BitcoinInspection>("/inspect/bitcoin"), ...poll });
  const lightning = createQuery({ queryKey: ["inspect", "lightning"], queryFn: () => get<LightningInspection>("/inspect/lightning"), ...poll });
  const btcpay = createQuery({ queryKey: ["inspect", "btcpay"], queryFn: () => get<BtcPayInspection>("/inspect/btcpay"), ...poll });

  const errorOf = (query: { isError: boolean; error: unknown }) =>
    query.isError ? (query.error as Error).message : null;
  const stamp = (..._updates: number[]) => new Date();
  $: now = stamp($bitcoin.dataUpdatedAt, $lightning.dataUpdatedAt, $btcpay.dataUpdatedAt);
</script>

<h2>Services</h2>
<p class="muted intro">State as last observed by this Rieko agent. Relative times use this device's clock.</p>

<div class="services" role="region" aria-label="Service status">
  <ServiceCard title="Bitcoin Core" icon="blocks" model={$bitcoin.data && coreCard($bitcoin.data, now)}
    loading={$bitcoin.isLoading} error={errorOf($bitcoin)} />
  <ServiceCard title="LND" icon="bolt" model={$lightning.data && lightningCard($lightning.data, now)}
    loading={$lightning.isLoading} error={errorOf($lightning)} />
  <ServiceCard title="BTCPay Server" icon="store" model={$btcpay.data && btcpayCard($btcpay.data, now)}
    loading={$btcpay.isLoading} error={errorOf($btcpay)} />
</div>

<Snapshots />

<style>
  .intro { margin: -0.5rem 0 var(--space-4); }
  .services {
    display: grid;
    gap: var(--space-3);
    grid-template-columns: repeat(auto-fit, minmax(min(240px, 100%), 1fr));
    margin-bottom: var(--space-5);
  }
</style>
