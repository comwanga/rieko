import { expect, test, type TestInfo } from "@playwright/test";
import { execFile, spawn } from "node:child_process";
import { access, mkdir, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
// This suite enters synthetic credentials. Keep bearer headers out of traces.
test.use({ trace: "off" });

async function withAgent(
  mode: "embedded" | "static",
  info: TestInfo,
  run: (url: string) => Promise<void>,
  token?: string,
  seed = false,
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
  const database = join(directory, "agent.db");
  if (seed) {
    // Real findings, recommendations and snapshots from the committed regtest
    // fixture, written by the real scan pipeline before the agent starts.
    const cli = join(repo, "target/debug", process.platform === "win32" ? "rieko.exe" : "rieko");
    await access(cli);
    await promisify(execFile)(cli, [
      "scan", "--network", "regtest", "--fixture", join(repo, "fixtures/channels.json"), "--db", database,
    ], { cwd: directory, env: environment, windowsHide: true });
  }
  const args = ["--addr", `127.0.0.1:${port}`, "--db", database, "--config", config];
  if (token) {
    const tokenFile = join(directory, "token.txt");
    await writeFile(tokenFile, token);
    args.push("--token-file", tokenFile);
  }
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
        if (response.status === (token ? 401 : 200)) break;
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
      if (token) expect(log.includes(token), "agent logs must not contain the token").toBe(false);
    }
  }
}

test.describe("token entry", () => {
  for (const mode of ["embedded", "static"] as const) {
    test(`${mode} protected agent supports login, reload and Forget`, async ({ page }, info) => {
      await withAgent(mode, info, async url => {
        const output: string[] = [];
        const urls: string[] = [];
        await page.addInitScript(() => {
          (window as typeof window & { authCsp: string[] }).authCsp = [];
          document.addEventListener("securitypolicyviolation", event => {
            (window as typeof window & { authCsp: string[] }).authCsp.push(event.effectiveDirective);
          });
        });
        page.on("request", request => urls.push(request.url()));
        page.on("console", message => output.push(message.text()));
        page.on("pageerror", error => output.push(error.message));
        let unauthorized = 0;
        page.on("response", response => { if (response.url() === `${url}/status` && response.status() === 401) unauthorized++; });
        await page.goto(url);
        await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
        expect(unauthorized).toBe(1);
        await expect(page.getByRole("region", { name: "System health" })).toHaveCount(0);
        await page.getByLabel("API token", { exact: true }).fill("synthetic-wrong-token");
        await page.getByRole("button", { name: "Unlock", exact: true }).click();
        await expect(page.getByText("Token not accepted. Check the token and try again.", { exact: true })).toBeVisible();
        expect(await page.evaluate(() => sessionStorage.getItem("rieko.apiToken"))).toBeNull();
        await unlock(page);
        const findings = page.waitForResponse(response => new URL(response.url()).pathname === "/findings" && response.status() === 200);
        await page.getByRole("link", { name: "Findings", exact: true }).click();
        expect((await findings).request().headers().authorization === "Bearer synthetic-browser-token").toBe(true);
        await page.getByRole("link", { name: "Overview", exact: true }).click();
        await expect(page.getByRole("region", { name: "System health" })).toBeVisible();
        await page.reload();
        await expect(page.getByRole("region", { name: "System health" })).toBeVisible();
        expect(await page.evaluate(() => sessionStorage.getItem("rieko.apiToken"))).toBe("synthetic-browser-token");
        expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain("synthetic-browser-token");
        expect(page.url()).not.toContain("synthetic-browser-token");
        await expect(page.locator("main")).not.toContainText("synthetic-browser-token");
        await page.getByRole("button", { name: "Forget token", exact: true }).click();
        await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
        await expect(page.getByRole("region", { name: "System health" })).toHaveCount(0);
        expect(await page.evaluate(() => sessionStorage.getItem("rieko.apiToken"))).toBeNull();
        await page.reload();
        await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
        expect(output.join("\n")).not.toContain("synthetic-browser-token");
        expect(urls.join("\n")).not.toContain("synthetic-browser-token");
        expect(await page.evaluate(() => (window as typeof window & { authCsp: string[] }).authCsp)).toEqual([]);
      }, "synthetic-browser-token");
    });
  }

  test("a rejected saved token is removed before prompting", async ({ page }, info) => {
    await page.addInitScript(() => sessionStorage.setItem("rieko.apiToken", "synthetic-revoked"));
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
      expect(await page.evaluate(() => sessionStorage.getItem("rieko.apiToken"))).toBeNull();
    }, "synthetic-browser-token");
  });

  test("blocked session storage still permits an in-memory login", async ({ page }, info) => {
    await page.addInitScript(() => Object.defineProperty(window, "sessionStorage", {
      get() { throw new DOMException("blocked", "SecurityError"); },
    }));
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
      await unlock(page);
      await expect(page.getByText("The current token is held in memory.", { exact: false })).toBeVisible();
      await page.reload();
      await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
      await expect(page.getByRole("region", { name: "System health" })).toHaveCount(0);
    }, "synthetic-browser-token");
  });

  test("failed removal is reported and Forget can be retried", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
      await unlock(page);
      await page.evaluate(() => {
        const original = Storage.prototype.removeItem;
        (window as typeof window & { restoreRemoval: () => void }).restoreRemoval = () => { Storage.prototype.removeItem = original; };
        Storage.prototype.removeItem = () => { throw new DOMException("blocked", "SecurityError"); };
      });
      await page.getByRole("button", { name: "Forget token", exact: true }).click();
      await expect(page.getByText("Browser storage could not be cleared", { exact: false })).toBeVisible();
      await expect(page.getByRole("region", { name: "System health" })).toHaveCount(0);
      expect(await page.evaluate(() => sessionStorage.getItem("rieko.apiToken"))).toBe("synthetic-browser-token");
      await page.evaluate(() => (window as typeof window & { restoreRemoval: () => void }).restoreRemoval());
      await page.getByRole("button", { name: "Forget token", exact: true }).click();
      await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
      expect(await page.evaluate(() => sessionStorage.getItem("rieko.apiToken"))).toBeNull();
    }, "synthetic-browser-token");
  });

  test("a delayed real status response cannot restore data after Forget", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
      await unlock(page);
      let release!: () => void;
      let captured!: () => void;
      const held = new Promise<void>(done => { release = done; });
      const intercepted = new Promise<void>(done => { captured = done; });
      await page.route(`${url}/status`, async route => {
        if (route.request().headers().authorization) {
          const response = await route.fetch();
          captured();
          await held;
          await route.fulfill({ response });
        } else await route.continue();
      });
      try {
        await page.getByRole("link", { name: "Findings", exact: true }).click();
        await page.getByRole("link", { name: "Overview", exact: true }).click();
        await intercepted;
        await page.getByRole("button", { name: "Forget token", exact: true }).click();
        await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
        const delivered = page.waitForResponse(response => response.url() === `${url}/status` && response.status() === 200);
        release();
        await delivered;
        // The old query may discard its body. Observe delivery, then let a fresh
        // real browser request complete before checking for stale UI state.
        expect(await page.evaluate(async () => (await fetch("/status")).status)).toBe(401);
        await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
        await expect(page.getByRole("region", { name: "System health" })).toHaveCount(0);
        expect(await page.evaluate(() => sessionStorage.getItem("rieko.apiToken"))).toBeNull();
      } finally { release(); }
    }, "synthetic-browser-token");
  });
});

async function unlock(page: import("@playwright/test").Page) {
  await page.getByLabel("API token", { exact: true }).fill("synthetic-browser-token");
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(page.getByRole("region", { name: "System health" })).toBeVisible();
}

type Page = import("@playwright/test").Page;

const VIEWS = [
  { id: "overview", link: "Overview", heading: "Overview", request: "/status" },
  { id: "findings", link: "Findings", heading: "Findings", request: "/findings" },
  { id: "recommendations", link: "Recommendations", heading: "Recommendations", request: "/recommendations" },
  { id: "simulations", link: "Simulations", heading: "Simulations", request: "/api/v2/simulations" },
  { id: "channels", link: "Channels", heading: "Channel liquidity", request: "/snapshots" },
  { id: "audit", link: "Audit", heading: "Audit log", request: "/audit" },
] as const;
const WIDTHS = [1440, 1024, 768, 390] as const;
const TEXT = [
  "aside a", "aside p", "aside h1", "aside button", "header button",
  "main h2", "main h3", "main h4", "main p", "main th", "main td", "main label", "main button",
  "main input", "main select", "main code", "main .tag", "main .kv > span",
].join(", ");

/** WCAG contrast of each visible, enabled text element against its effective background. */
async function textContrast(page: Page) {
  return page.locator(TEXT).evaluateAll(elements => {
    const rgb = (value: string) => value.match(/[\d.]+/g)!.map(Number);
    const luminance = (color: number[]) => {
      const linear = color.slice(0, 3).map(value => {
        value /= 255;
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      });
      return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722;
    };
    const results: { text: string; ratio: number }[] = [];
    for (const element of elements) {
      const control = element.matches("input, select, button");
      const ownText = Array.from(element.childNodes).some(node => node.nodeType === 3 && node.textContent!.trim() !== "");
      if (!control && !ownText) continue;
      if ((element as HTMLButtonElement).disabled || element.getClientRects().length === 0) continue;
      let background = "";
      for (let current: Element | null = element; current; current = current.parentElement) {
        const candidate = getComputedStyle(current).backgroundColor;
        const parts = rgb(candidate);
        if (parts.length === 3 || parts[3] === 1) { background = candidate; break; }
      }
      if (!background) background = getComputedStyle(document.documentElement).backgroundColor;
      const values = [luminance(rgb(getComputedStyle(element).color)), luminance(rgb(background))].sort((a, b) => a - b);
      results.push({
        text: `${element.tagName.toLowerCase()}.${element.className}: ${(element.textContent ?? "").trim().slice(0, 40)}`,
        ratio: (values[1] + 0.05) / (values[0] + 0.05),
      });
    }
    return results;
  });
}

async function expectReadable(page: Page, context: string) {
  const results = await textContrast(page);
  expect(results.length, `${context}: text was measured`).toBeGreaterThan(0);
  const failures = results.filter(result => result.ratio < 4.5);
  expect(failures, `${context}: text below 4.5:1`).toEqual([]);
}

async function useTheme(page: Page, theme: "dark" | "light") {
  if (await page.evaluate(() => document.documentElement.dataset.theme) !== theme) {
    await page.getByRole("button", { name: `Use ${theme} theme`, exact: true }).click();
  }
  await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
}

test.describe("application shell", () => {
  test("dark shell with landmarks, six view links and rendered separators", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      await expect(page.getByRole("region", { name: "System health" })).toBeVisible();
      await expect(page.locator("main")).not.toContainText(String.raw`\xb7`);
      await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
      const navigation = page.getByRole("navigation", { name: "Primary", exact: true });
      await expect(navigation.getByRole("link")).toHaveText(VIEWS.map(view => view.link));
      await expect(navigation.getByRole("link", { name: "Overview", exact: true })).toHaveAttribute("aria-current", "page");
      await expect(page.getByRole("main")).toHaveCount(1);
      await expect(page.getByRole("banner")).toHaveCount(1);
      const colour = (selector: string) => page.locator(selector).first().evaluate(element => getComputedStyle(element).backgroundColor);
      // Token values sampled from the approved reference image.
      expect(await colour("body")).toBe("rgb(9, 15, 21)");
      expect(await colour("aside")).toBe("rgb(10, 16, 22)");
      expect(await colour("header")).toBe("rgb(13, 19, 25)");
      expect(await colour("main .card")).toBe("rgb(17, 24, 31)");
      expect(await colour("nav a[aria-current=page]")).toBe("rgb(30, 48, 68)");
      for (const name of ["Documentation", "GitHub"]) {
        const link = page.getByRole("link", { name, exact: false });
        await expect(link).toHaveAttribute("target", "_blank");
        await expect(link).toHaveAttribute("rel", "noopener noreferrer");
        expect(await link.getAttribute("href")).toMatch(/^https:\/\/github\.com\/comwanga\/rieko/);
      }
    });
  });

  for (const mode of ["embedded", "static"] as const) {
    test(`${mode} views have URLs, history and unchanged requests without CSP violations`, async ({ page }, info) => {
      await withAgent(mode, info, async url => {
        await page.addInitScript(() => {
          const state = window as typeof window & { shellCsp: string[] };
          state.shellCsp = [];
          document.addEventListener("securitypolicyviolation", event => state.shellCsp.push(event.effectiveDirective));
        });
        const errors: string[] = [];
        page.on("pageerror", error => errors.push(error.message));
        await page.goto(`${url}/#/findings`);
        await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();
        await expect(page.getByRole("link", { name: "Findings", exact: true })).toHaveAttribute("aria-current", "page");
        for (const view of VIEWS) {
          const response = page.waitForResponse(candidate =>
            new URL(candidate.url()).pathname === view.request && candidate.request().method() === "GET");
          await page.getByRole("link", { name: view.link, exact: true }).click();
          expect((await response).status()).toBe(200);
          await expect(page.getByRole("heading", { name: view.heading, exact: true })).toBeVisible();
          expect(new URL(page.url()).hash).toBe(`#/${view.id}`);
          await expect(page).toHaveTitle(`${view.link} · Rieko`);
          await expect(page.locator("nav a[aria-current=page]")).toHaveText([view.link]);
        }
        await page.goBack();
        await expect(page.getByRole("heading", { name: "Channel liquidity", exact: true })).toBeVisible();
        await page.goForward();
        await expect(page.getByRole("heading", { name: "Audit log", exact: true })).toBeVisible();
        await page.goto(`${url}/#/no-such-view`);
        await expect(page.getByRole("region", { name: "System health" })).toBeVisible();
        await expect(page.locator("nav a[aria-current=page]")).toHaveText(["Overview"]);
        expect(errors).toEqual([]);
        expect(await page.evaluate(() => (window as typeof window & { shellCsp: string[] }).shellCsp)).toEqual([]);
      });
    });
  }

  test("keyboard reaches the skip control, links and view heading with a visible focus ring", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      await expect(page.getByRole("region", { name: "System health" })).toBeVisible();
      await page.keyboard.press("Tab");
      await expect(page.getByRole("button", { name: "Skip to content", exact: true })).toBeFocused();
      await page.keyboard.press("Enter");
      await expect(page.locator("main")).toBeFocused();
      const findings = page.getByRole("link", { name: "Findings", exact: true });
      await findings.focus();
      await page.keyboard.press("Shift+Tab");
      await page.keyboard.press("Tab");
      await expect(findings).toBeFocused();
      const ring = await findings.evaluate(element => {
        const style = getComputedStyle(element);
        return { style: style.outlineStyle, width: parseFloat(style.outlineWidth), colour: style.outlineColor,
          surface: getComputedStyle(element.closest("aside")!).backgroundColor };
      });
      expect(ring.style).not.toBe("none");
      expect(ring.width).toBeGreaterThanOrEqual(2);
      const luminance = (value: string) => {
        const linear = value.match(/[\d.]+/g)!.slice(0, 3).map(Number).map(part => {
          part /= 255;
          return part <= 0.04045 ? part / 12.92 : ((part + 0.055) / 1.055) ** 2.4;
        });
        return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722;
      };
      const pair = [luminance(ring.colour), luminance(ring.surface)].sort((a, b) => a - b);
      expect((pair[1] + 0.05) / (pair[0] + 0.05)).toBeGreaterThanOrEqual(3);
      await page.keyboard.press("Enter");
      await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeFocused();
    });
  });

  test("reselecting the current view from the collapsed menu keeps keyboard focus on the view", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.setViewportSize({ width: 390, height: 900 });
      await page.goto(`${url}/#/findings`);
      await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();
      const menu = page.getByRole("button", { name: "Menu", exact: true });
      await menu.focus();
      await page.keyboard.press("Enter");
      await expect(menu).toHaveAttribute("aria-expanded", "true");
      const current = page.getByRole("link", { name: "Findings", exact: true });
      await current.focus();
      await page.keyboard.press("Enter");
      await expect(menu).toHaveAttribute("aria-expanded", "false");
      expect(new URL(page.url()).hash).toBe("#/findings");
      await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeFocused();
    });
  });

  test("theme choice persists, never touches the token key and survives blocked storage", async ({ page, context }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      await expect(page.getByRole("region", { name: "System health" })).toBeVisible();
      await useTheme(page, "light");
      expect(await page.locator("body").evaluate(element => getComputedStyle(element).backgroundColor)).toBe("rgb(244, 245, 247)");
      expect(await page.evaluate(() => Object.keys(localStorage))).toEqual(["rieko.theme"]);
      expect(await page.evaluate(() => Object.keys(sessionStorage))).toEqual([]);
      await page.reload();
      await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
      await useTheme(page, "dark");
      await page.reload();
      await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

      const blocked = await context.newPage();
      await blocked.addInitScript(() => Object.defineProperty(window, "localStorage", {
        get() { throw new DOMException("blocked", "SecurityError"); },
      }));
      await blocked.goto(url);
      await expect(blocked.getByRole("region", { name: "System health" })).toBeVisible();
      await expect(blocked.locator("html")).toHaveAttribute("data-theme", "dark");
      await useTheme(blocked, "light");
      await expect(blocked.getByRole("region", { name: "System health" })).toBeVisible();
      await blocked.close();
    });
  });

  test("no horizontal scroll and an operable menu at every width in both themes", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      for (const theme of ["dark", "light"] as const) {
        for (const width of WIDTHS) {
          await page.setViewportSize({ width, height: 900 });
          await page.goto(`${url}/#/overview`);
          await useTheme(page, theme);
          const menu = page.getByRole("button", { name: "Menu", exact: true });
          const navigation = page.getByRole("navigation", { name: "Primary", exact: true });
          if (width < 1024) {
            await expect(menu).toHaveAttribute("aria-expanded", "false");
            await expect(navigation).toBeHidden();
          } else await expect(menu).toBeHidden();
          for (const view of VIEWS) {
            if (width < 1024) {
              await menu.focus();
              await page.keyboard.press("Enter");
              await expect(menu).toHaveAttribute("aria-expanded", "true");
            }
            await page.getByRole("link", { name: view.link, exact: true }).click();
            await expect(page.getByRole("heading", { name: view.heading, exact: true })).toBeVisible();
            if (width < 1024) await expect(navigation).toBeHidden();
            const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
            expect(overflow, `${theme} ${width}px ${view.id}`).toBeLessThanOrEqual(0);
          }
        }
      }
    });
  });

  test("seeded views stay readable in both themes and the simulation form still submits", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(`${url}/#/recommendations`);
      const simulate = page.getByRole("button", { name: "Simulate", exact: true }).first();
      await expect(simulate).toBeVisible();
      for (const theme of ["dark", "light"] as const) {
        await useTheme(page, theme);
        for (const view of VIEWS) {
          await page.getByRole("link", { name: view.link, exact: true }).click();
          await expect(page.getByRole("heading", { name: view.heading, exact: true })).toBeVisible();
          if (view.id !== "overview" && view.id !== "simulations") await expect(page.locator("main tbody tr").first()).toBeVisible();
          await expectReadable(page, `${theme} ${view.id}`);
        }
        await page.getByRole("link", { name: "Recommendations", exact: true }).click();
        await simulate.click();
        const dialog = page.getByRole("dialog", { name: "Create simulation", exact: true });
        await expect(dialog).toBeVisible();
        await expectReadable(page, `${theme} simulation dialog`);
        if (theme === "dark") await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
      }
      const dialog = page.getByRole("dialog", { name: "Create simulation", exact: true });
      const options = await dialog.getByLabel("Source channel", { exact: true }).locator("option").evaluateAll(
        elements => elements.map(element => (element as HTMLOptionElement).value).filter(Boolean));
      expect(options.length).toBeGreaterThanOrEqual(2);
      await dialog.getByLabel("Source channel", { exact: true }).selectOption(options[0]);
      await dialog.getByLabel("Destination channel", { exact: true }).selectOption(options[1]);
      await dialog.getByLabel("Amount in sats", { exact: true }).fill("1000");
      const submitted = page.waitForResponse(response =>
        new URL(response.url()).pathname === "/api/v2/simulations" && response.request().method() === "POST");
      await dialog.getByRole("button", { name: "Run simulation", exact: true }).click();
      const response = await submitted;
      expect(response.request().postDataJSON()).toMatchObject({
        model_id: "liquidity-redistribution", source_channel: options[0], destination_channel: options[1], amount_sats: 1000,
      });
      // The committed fixture cannot produce a successful simulation: its channels
      // carry no reserve data, so spendable outbound liquidity is 0 and the model
      // refuses with invalid_input. Its observation time is the fixture file's
      // modification time, so a checkout older than the staleness window is
      // refused earlier, with stale_input. Either way this proves the form sends
      // the expected request and shows the server's refusal. The success and
      // compare paths are not exercised in the browser.
      expect(response.ok(), "the fixture cannot produce a successful simulation").toBe(false);
      const refusal = await response.json();
      expect([400, 409]).toContain(response.status());
      expect(["invalid_input", "stale_input"]).toContain(refusal.error.code);
      await expect(dialog).toBeVisible();
      await expect(dialog.getByRole("alert")).toContainText(String(response.status()));
    }, undefined, true);
  });

  test("the token prompt is readable in both themes", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
      for (const theme of ["dark", "light"] as const) {
        await useTheme(page, theme);
        await expectReadable(page, `${theme} token prompt`);
      }
    }, "synthetic-browser-token");
  });
});

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
