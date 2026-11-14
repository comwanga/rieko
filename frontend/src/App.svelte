<script lang="ts">
  import { QueryClient, QueryClientProvider } from "@tanstack/svelte-query";
  import { onDestroy, tick } from "svelte";
  import { AuthenticationError, authState, initializeAuth } from "./lib/auth";
  import { route, routeParam, startRouter } from "./lib/router";
  import Sidebar from "./lib/Sidebar.svelte";
  import TokenPrompt from "./lib/TokenPrompt.svelte";
  import TopBar from "./lib/TopBar.svelte";
  import FindingDetail from "./pages/FindingDetail.svelte";
  import Findings from "./pages/Findings.svelte";
  import Services from "./pages/Services.svelte";
  import Status from "./pages/Status.svelte";
  import Audit from "./pages/Audit.svelte";
  import Recommendations from "./pages/Recommendations.svelte";
  import Simulations from "./pages/Simulations.svelte";

  initializeAuth();
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: (failures, error) => !(error instanceof AuthenticationError) && failures < 3 } },
  });
  let observedGeneration = -1;
  const unsubscribe = authState.subscribe(state => {
    if (state.generation !== observedGeneration) {
      queryClient.clear();
      observedGeneration = state.generation;
    }
  });

  let content: HTMLElement;
  // After the reader chooses a view, move focus to its heading so keyboard and
  // screen-reader users land on the new content. Not done on the initial load.
  async function focusView() {
    await tick();
    const heading = content?.querySelector<HTMLElement>("h2");
    if (heading) {
      heading.tabIndex = -1;
      heading.focus();
    }
  }
  const stopRouter = startRouter(focusView);
  onDestroy(() => { stopRouter(); unsubscribe(); queryClient.clear(); });
</script>

<QueryClientProvider client={queryClient}>
  <button class="skip" on:click={() => content.focus()}>Skip to content</button>
  <div class="layout">
    <Sidebar onReselect={focusView} />
    <div class="content">
      <TopBar />
      <main bind:this={content} tabindex="-1">
        {#if $authState.storage === "clear-failed"}
          <p class="critical" role="alert">Browser storage could not be cleared; a saved token may remain. Clear this site's session data before reloading, or retry Forget token after restoring storage access. {#if $authState.hasToken}The current token is held in memory.{/if}</p>
        {:else if $authState.storage === "memory"}
          <p class="muted" role="status">Session storage is unavailable. This page will use memory for the token.</p>
        {/if}
        {#key $authState.generation}
        {#if $authState.required}
          <TokenPrompt />
        {:else if $route === "overview"}
          <Status />
        {:else if $route === "findings"}
          {#if $routeParam}
            {#key $routeParam}<FindingDetail id={$routeParam} />{/key}
          {:else}
            <Findings />
          {/if}
        {:else if $route === "recommendations"}
          <Recommendations />
        {:else if $route === "simulations"}
          <Simulations />
        {:else if $route === "services"}
          <Services />
        {:else}
          <Audit />
        {/if}
        {/key}
      </main>
    </div>
  </div>
</QueryClientProvider>
