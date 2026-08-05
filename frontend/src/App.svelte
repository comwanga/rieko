<script lang="ts">
  import Findings from "./pages/Findings.svelte";
  import Snapshots from "./pages/Snapshots.svelte";
  import Status from "./pages/Status.svelte";
  import Audit from "./pages/Audit.svelte";

  type Tab = "status" | "findings" | "snapshots" | "audit";
  let tab: Tab = "status";
</script>

<main>
  <header>
    <h1>Rieko</h1>
    <nav>
      <button class:active={tab === "status"} on:click={() => (tab = "status")}>Overview</button>
      <button class:active={tab === "findings"} on:click={() => (tab = "findings")}>Findings</button>
      <button class:active={tab === "snapshots"} on:click={() => (tab = "snapshots")}>Channels</button>
      <button class:active={tab === "audit"} on:click={() => (tab = "audit")}>Audit</button>
    </nav>
  </header>

  {#if tab === "status"}
    <Status />
  {:else if tab === "findings"}
    <Findings />
  {:else if tab === "snapshots"}
    <Snapshots />
  {:else}
    <Audit />
  {/if}
</main>

<style>
  header {
    display: flex;
    align-items: center;
    gap: 1.5rem;
    margin-bottom: 1rem;
  }
  nav {
    display: flex;
    gap: 0.25rem;
  }
  button {
    border: 1px solid transparent;
    background: transparent;
    border-radius: 6px;
    padding: 0.35rem 0.8rem;
    cursor: pointer;
    font-size: 0.9rem;
  }
  button.active {
    background: #1a1a2e;
    color: #fff;
  }
</style>