import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testMatch: ["browser-smoke.spec.ts", "api-auth.spec.ts", "overview-model.spec.ts", "findings-model.spec.ts"],
  timeout: 30_000,
  // The Overview tests wait on real agent polling of mock sources.
  globalTimeout: 240_000,
  workers: 1,
  retries: 0,
  forbidOnly: Boolean(process.env.CI),
  reporter: "list",
  use: {
    browserName: "chromium",
    headless: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
});
