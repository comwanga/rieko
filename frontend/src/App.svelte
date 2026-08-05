<script lang="ts">
  import Findings from "./pages/Findings.svelte";
  import Snapshots from "./pages/Snapshots.svelte";
  import Simulations from "./pages/Simulations.svelte";
  import Actions from "./pages/Actions.svelte";

  type Tab = "findings" | "snapshots" | "simulations" | "actions";
  let tab: Tab = "findings";
</script>

<main>
  <header>
    <h1>Rieko</h1>
    <nav>
      <button class:active={tab === "findings"} on:click={() => (tab = "findings")}>Findings</button>
      <button class:active={tab === "snapshots"} on:click={() => (tab = "snapshots")}>Channels</button>
      <button class:active={tab === "simulations"} on:click={() => (tab = "simulations")}>Simulations</button>
      <button class:active={tab === "actions"} on:click={() => (tab = "actions")}>Actions</button>
    </nav>
  </header>

  {#if tab === "findings"}
    <Findings />
  {:else if tab === "snapshots"}
    <Snapshots />
  {:else if tab === "simulations"}
    <Simulations />
  {:else}
    <Actions />
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