<script lang="ts">
  import { authState, forgetToken } from "./auth";
  import Icon from "./Icon.svelte";
  import { setTheme, theme } from "./theme";

  $: next = $theme === "dark" ? ("light" as const) : ("dark" as const);
</script>

<header>
  {#if $authState.hasToken || $authState.required || $authState.storage === "clear-failed"}
    <button on:click={forgetToken}>Forget token</button>
  {/if}
  <button class="theme" aria-label="Use {next} theme" on:click={() => setTheme(next)}>
    <Icon name={next === "light" ? "sun" : "moon"} />
  </button>
</header>

<style>
  header {
    align-items: center;
    background: var(--surface-topbar);
    border-bottom: 1px solid var(--border);
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
    min-height: 3rem;
    padding: var(--space-2) var(--space-5);
  }
  .theme { display: inline-flex; padding: 0.45rem; }
</style>
