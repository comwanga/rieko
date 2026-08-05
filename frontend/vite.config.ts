import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Built output (`dist/`) is served by the Rust binary (axum) so there is
// exactly one runtime in production (ADR D2). `apiBase` is overridden at
// runtime by the Rust server injecting a small config script; the default
// here is only for local `npm run dev`.
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});