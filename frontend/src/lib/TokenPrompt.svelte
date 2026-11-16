<script lang="ts">
  import { authenticate } from "./api";
  let token = "";
  let pending = false;
  let error = "";

  async function submit() {
    if (pending) return;
    pending = true;
    error = "";
    try {
      await authenticate(token);
      token = "";
    } catch (failure) {
      error = failure instanceof TypeError ? "Could not reach the API. Try again." : (failure as Error).message;
    } finally { pending = false; }
  }
</script>

<section class="card" aria-label="API authentication">
  <h2>API token required</h2>
  <p id="token-help">Enter the raw token configured for this Rieko API. Session storage can retain it across reloads and browser session restores.</p>
  <form on:submit|preventDefault={submit}>
    <label for="api-token">API token</label>
    <input id="api-token" type="password" bind:value={token} autocomplete="off" spellcheck="false" aria-describedby="token-help" disabled={pending} />
    <button type="submit" disabled={pending}>{pending ? "Checking…" : "Unlock"}</button>
  </form>
  {#if error}<p class="critical" role="alert">{error}</p>{/if}
</section>

<style>
  form { display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; }
  input, button { padding: 0.5rem; }
</style>
