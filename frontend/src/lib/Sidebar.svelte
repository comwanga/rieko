<script lang="ts">
  import Icon from "./Icon.svelte";
  import { ROUTES, route, routeHref } from "./router";

  const REPOSITORY = "https://github.com/comwanga/rieko";
  /** Called when the link for the view already shown is activated: the URL
      does not change, so the router does not move focus by itself. */
  export let onReselect: () => void = () => {};
  let open = false;

  function select(id: string) {
    open = false;
    if (id === $route) onReselect();
  }
</script>

<aside>
  <div class="brand">
    <span class="mark"><Icon name="logo" /></span>
    <div>
      <h1>Rieko</h1>
      <p>Bitcoin Infrastructure Observability</p>
    </div>
    <button class="menu" aria-expanded={open} aria-controls="primary-navigation" on:click={() => (open = !open)}>
      <Icon name="menu" /> Menu
    </button>
  </div>

  <nav id="primary-navigation" aria-label="Primary" class:open>
    {#each ROUTES as item}
      <a href={routeHref(item.id)} aria-current={$route === item.id ? "page" : undefined} on:click={() => select(item.id)}>
        <Icon name={item.icon} /> {item.label}
      </a>
    {/each}
  </nav>

  <div class="links" class:open>
    <a href="{REPOSITORY}#readme" target="_blank" rel="noopener noreferrer">Documentation <Icon name="external" /></a>
    <a href={REPOSITORY} target="_blank" rel="noopener noreferrer">GitHub <Icon name="external" /></a>
  </div>
</aside>

<style>
  aside {
    background: var(--surface-sidebar);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    padding: var(--space-4);
  }
  .brand { display: flex; align-items: center; gap: var(--space-3); }
  .brand > div { flex: 1; min-width: 0; }
  .mark { color: var(--accent); display: flex; }
  .mark :global(svg) { width: 28px; height: 28px; }
  h1 { font-size: 1.35rem; margin: 0; }
  p { color: var(--text-muted); font-size: 0.8rem; margin: 0.15rem 0 0; }
  nav { display: flex; flex-direction: column; gap: var(--space-1); }
  a {
    align-items: center;
    border-radius: var(--radius);
    color: var(--text);
    display: flex;
    gap: var(--space-3);
    padding: 0.55rem 0.75rem;
    text-decoration: none;
  }
  nav a:hover { background: var(--surface-input); }
  nav a[aria-current="page"] { background: var(--surface-active); color: var(--text-on-active); font-weight: 600; }
  .links {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    display: flex;
    flex-direction: column;
    font-size: 0.85rem;
    margin-top: auto;
    padding: var(--space-2);
  }
  .links a { color: var(--text-muted); padding: 0.3rem 0.5rem; }
  .links :global(svg) { width: 14px; height: 14px; }
  .menu { display: none; }

  @media (max-width: 1023.98px) {
    aside { border-bottom: 1px solid var(--border); border-right: 0; gap: var(--space-2); padding: var(--space-3) var(--space-4); }
    .menu { align-items: center; display: inline-flex; gap: var(--space-2); }
    nav, .links { display: none; }
    nav.open, .links.open { display: flex; }
    .links { margin-top: 0; }
  }
</style>
