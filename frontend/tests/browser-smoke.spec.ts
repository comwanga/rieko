import { expect, test, type TestInfo } from "@playwright/test";
import { spawn } from "node:child_process";
import { access, mkdir, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

async function withAgent(
  mode: "embedded" | "static",
  info: TestInfo,
  run: (url: string) => Promise<void>,
) {
  const binary = join(repo, "target/debug", process.platform === "win32" ? "rieko-agent.exe" : "rieko-agent");
  await access(binary);
  await access(join(repo, "frontend/dist/index.html"));
  const directory = info.outputPath("agent");
  await mkdir(directory, { recursive: true });
  const config = join(directory, "config.json");
  await writeFile(config, JSON.stringify({ version: 1, btcpay: null }));

  const reservation = createServer();
  await new Promise<void>((ready, reject) => {
    reservation.once("error", reject);
    reservation.listen(0, "127.0.0.1", ready);
  });
  const address = reservation.address();
  if (!address || typeof address === "string") throw new Error("No loopback test port");
  const port = address.port;
  await new Promise<void>((done, reject) => reservation.close(error => error ? reject(error) : done()));

  const environment = Object.fromEntries(Object.entries(process.env).filter(
    ([key]) => !/^(RIEKO_|OPENAI_|TELEGRAM_)/i.test(key),
  ));
  const args = ["--addr", `127.0.0.1:${port}`, "--db", join(directory, "agent.db"), "--config", config];
  if (mode === "static") args.push("--static-dir", join(repo, "frontend/dist"));
  const agent = spawn(binary, args, {
    cwd: directory, env: environment, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  let spawnError: Error | undefined;
  agent.on("error", error => { spawnError = error; });
  agent.stdout.on("data", chunk => { log += chunk.toString(); });
  agent.stderr.on("data", chunk => { log += chunk.toString(); });
  const closed = new Promise<void>(done => agent.once("close", () => done()));
  const url = `http://127.0.0.1:${port}`;
  try {
    const deadline = Date.now() + 10_000;
    while (true) {
      if (spawnError) throw spawnError;
      if (agent.exitCode !== null || agent.signalCode !== null) {
        throw new Error(`Agent exited before readiness:\n${log}`);
      }
      try {
        const response = await fetch(`${url}/status`, { signal: AbortSignal.timeout(500) });
        if (response.ok) break;
      } catch { /* Retry until the fixture process starts listening. */ }
      if (Date.now() >= deadline) throw new Error(`Agent readiness timed out:\n${log}`);
      await delay(50);
    }
    await run(url);
    expect(agent.exitCode, "the fixture agent must remain alive").toBeNull();
  } finally {
    const forceStop = setTimeout(() => agent.kill("SIGKILL"), 5_000);
    forceStop.unref();
    try {
      if (agent.exitCode === null && agent.signalCode === null) agent.kill();
      await closed;
    } finally {
      clearTimeout(forceStop);
      await info.attach("agent-log", { body: log, contentType: "text/plain" });
    }
  }
}

for (const mode of ["embedded", "static"] as const) {
  test(`${mode} Overview renders real status without CSP violations`, async ({ page }, info) => {
    await withAgent(mode, info, async url => {
      const pageErrors: string[] = [];
      page.on("pageerror", error => pageErrors.push(error.message));
      await page.addInitScript(() => {
        const state = window as typeof window & { cspViolations: string[] };
        state.cspViolations = [];
        document.addEventListener("securitypolicyviolation", event => {
          state.cspViolations.push(`${event.effectiveDirective}: ${event.blockedURI}`);
        });
      });
      const statusResponses: import("@playwright/test").Response[] = [];
      page.on("response", response => {
        if (response.url() === `${url}/status`) statusResponses.push(response);
      });
      try {
        const document = await page.goto(url);
        expect(document?.status()).toBe(200);
        const health = page.getByRole("region", { name: "System health", exact: true });
        await expect(health).toBeVisible({ timeout: 10_000 });
        expect(statusResponses.length, "Overview must fetch status from the real agent").toBeGreaterThan(0);
        const response = statusResponses.at(-1)!;
        expect(response.status()).toBe(200);
        const status = await response.json();
        await expect(health.getByRole("status")).toHaveText([status.overall, status.integrity]);
        await expect(page.getByRole("region", { name: "Record counts", exact: true })).toContainText(String(status.counts.findings));
        await expect(page.getByText(`${status.engine} v${status.version}`, { exact: false })).toBeVisible();
        expect(document?.headers()["content-security-policy"]).toContain("connect-src 'self'");
        expect(pageErrors).toEqual([]);
        const cspViolations = await page.evaluate(() => (window as typeof window & { cspViolations: string[] }).cspViolations);
        expect(cspViolations).toEqual([]);
        await writeFile(info.outputPath("browser-status.json"), JSON.stringify({ mode, status, pageErrors, cspViolations }, null, 2));
      } finally {
        const violations = await page.evaluate(() => (window as typeof window & { cspViolations?: string[] }).cspViolations).catch(() => null);
        await info.attach("browser-errors", {
          body: JSON.stringify({ pageErrors, cspViolations: violations }, null, 2), contentType: "application/json",
        });
      }
    });
  });
}
