import { expect, test, type TestInfo } from "@playwright/test";
import { execFile, spawn } from "node:child_process";
import { access, mkdir, writeFile } from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import { createServer, type AddressInfo } from "node:net";
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
  extraArgs: string[] = [],
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
  args.push(...extraArgs);
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
  { id: "services", link: "Services", heading: "Services", request: "/snapshots" },
  { id: "audit", link: "Audit", heading: "Audit log", request: "/audit" },
] as const;
const WIDTHS = [1440, 1024, 768, 390] as const;
const TEXT = [
  "aside a", "aside p", "aside h1", "aside button", "header button",
  "main h2", "main h3", "main h4", "main p", "main th", "main td", "main label", "main button",
  "main input", "main select", "main code", "main .tag", "main .kv > span",
  "main dt", "main dd", "main li", "main a", "main .badge", "main small", "header a",
  "main pre", "main strong", "main span", "aside .nav-count",
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
        await expect(page.getByRole("heading", { name: "Services", exact: true })).toBeVisible();
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

// ─── Overview (MS-2.3b) ───

const PIPELINE: Record<string, string> = {
  healthy: "Healthy", degraded: "Degraded", unhealthy: "Unhealthy", not_initialized: "Not initialized",
};
const SERVICES = ["Bitcoin Core", "LND", "BTCPay Server"] as const;

/** A card's term/definition pairs, keyed by term. */
async function cardValues(page: Page, name: string) {
  const card = page.getByRole("region", { name: "System health", exact: true }).getByRole("region", { name, exact: true });
  const terms = await card.getByRole("term").allTextContents();
  const values = await card.getByRole("definition").allTextContents();
  expect(values.length).toBe(terms.length);
  return Object.fromEntries(terms.map((term, index) => [term.trim(), values[index].trim()]));
}

function card(page: Page, name: string) {
  return page.getByRole("region", { name: "System health", exact: true }).getByRole("region", { name, exact: true });
}

interface MockSource { url: string; stop(): Promise<void> }

/** A loopback JSON server standing in for a real service. Its responses follow our
    reading of each service's API; only the regtest workflow checks real services. */
async function mockSource(respond: (method: string, path: string) => unknown): Promise<MockSource> {
  const server = createHttpServer((request, response) => {
    request.resume();
    const body = respond(request.method ?? "GET", new URL(request.url ?? "/", "http://mock").pathname);
    if (body === undefined) response.writeHead(404).end();
    else response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
  });
  await new Promise<void>(ready => server.listen(0, "127.0.0.1", ready));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    stop: () => new Promise<void>(done => { server.closeAllConnections(); server.close(() => done()); }),
  };
}

const CORE_RESULT = { chain: "regtest", blocks: 250, headers: 250, initialblockdownload: false };
const LND_INFO = {
  identity_pubkey: `02${"ab".repeat(32)}`, alias: "mock-node", version: "0.18.5-beta",
  chains: [{ chain: "bitcoin", network: "regtest" }], synced_to_chain: true,
  num_active_channels: 3, num_inactive_channels: 1,
};

const mockCore = () => mockSource(method => method === "POST"
  ? { result: CORE_RESULT, error: null, id: "rieko-core-observation" } : undefined);
const mockLnd = () => mockSource((_, path) => path === "/v1/getinfo" ? LND_INFO : undefined);
const mockBtcPay = () => mockSource((_, path) => {
  if (path === "/api/v1/server/info") return { version: "2.1.0", supportedPaymentMethods: ["BTC"], fullySynced: true };
  if (path.endsWith("/lightning/BTC/info")) return { nodeURIs: [`${LND_INFO.identity_pubkey}@127.0.0.1:9735`], blockHeight: 250 };
  if (path.endsWith("/lightning/BTC/channels")) return [];
  if (path.endsWith("/onchain/BTC/wallet")) return { balance: "0", confirmedBalance: "0", unconfirmedBalance: "0" };
  return undefined;
});

/** Agent flags for the given mock sources, with synthetic credentials in files. */
async function sourceArgs(info: TestInfo, sources: { core?: string; lnd?: string; btcpay?: string }) {
  const directory = info.outputPath("sources");
  await mkdir(directory, { recursive: true });
  const args: string[] = [];
  if (sources.core) {
    await writeFile(join(directory, "core-password"), "synthetic-core-password");
    args.push("--bitcoin-core-rpc-url", sources.core, "--bitcoin-core-rpc-user", "rieko",
      "--bitcoin-core-rpc-password-file", join(directory, "core-password"),
      "--bitcoin-core-poll-interval", "1", "--bitcoin-core-poll-timeout", "2");
  }
  if (sources.lnd) {
    await writeFile(join(directory, "macaroon"), Buffer.from([0xde, 0xad, 0xbe, 0xef]));
    args.push("--lnd-rest-url", sources.lnd, "--lnd-macaroon-file", join(directory, "macaroon"),
      "--lnd-network", "regtest", "--lnd-allow-insecure", "--lnd-poll-interval", "1", "--lnd-poll-timeout", "2");
  }
  if (sources.btcpay) {
    await writeFile(join(directory, "btcpay-key"), "synthetic-greenfield-key");
    args.push("--btcpay-greenfield-url", sources.btcpay, "--btcpay-greenfield-api-key-file", join(directory, "btcpay-key"),
      "--btcpay-greenfield-store", "store-test", "--btcpay-greenfield-network", "regtest",
      "--btcpay-poll-interval", "1", "--btcpay-poll-timeout", "2");
  }
  return args;
}

/** Poll an agent endpoint (not through the UI) until `ready` holds. */
async function waitFor(url: string, path: string, ready: (body: any) => boolean) {
  const deadline = Date.now() + 15_000;
  for (;;) {
    const body = await (await fetch(`${url}${path}`)).json();
    if (ready(body)) return body;
    if (Date.now() > deadline) throw new Error(`${path} did not become ready: ${JSON.stringify(body)}`);
    await delay(100);
  }
}

async function freePort() {
  const reservation = createServer();
  await new Promise<void>(ready => reservation.listen(0, "127.0.0.1", ready));
  const { port } = reservation.address() as AddressInfo;
  await new Promise<void>(done => reservation.close(() => done()));
  return port;
}

test.describe("Overview", () => {
  test("with no sources every service is not observed and no value is invented", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      const statusResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/status");
      await page.goto(url);
      const status = await (await statusResponse).json();
      for (const name of SERVICES) {
        await expect(card(page, name).locator(".badge")).toHaveText("Not observed");
        await expect(card(page, name).getByRole("definition")).toHaveCount(0);
      }
      await expect(card(page, "Rieko").locator(".badge")).toHaveText(`Pipeline: ${PIPELINE[status.overall]}`);
      await expect(page.getByRole("link", { name: /^Rieko pipeline:/ })).toHaveText(`Rieko pipeline: ${PIPELINE[status.overall]}`);
      await expect(page.getByRole("region", { name: "Active findings", exact: true })).toContainText("No active findings");
      await expect(page.locator("body")).not.toContainText("All systems operational");
    });
  });

  test("Core and LND values equal the API; BTCPay stays not observed despite a default state row (M2b)", async ({ page }, info) => {
    const core = await mockCore();
    const lnd = await mockLnd();
    try {
      await withAgent("embedded", info, async url => {
        const bitcoin = await waitFor(url, "/inspect/bitcoin", body => body.state?.connected === true);
        const lightning = await waitFor(url, "/inspect/lightning", body => body.state?.connected === true);
        // M2b reproduced at runtime: no BTCPay is configured, yet the shared state
        // row exists with the default fixture source.
        const btcpay = await (await fetch(`${url}/inspect/btcpay`)).json();
        const status = await (await fetch(`${url}/status`)).json();
        expect(btcpay.state?.source).toBe("Fixture");
        expect(status.source).toBe("fixture");
        expect(status.last_ingestion?.success ?? null).toBeNull();

        await page.goto(url);
        await expect(card(page, "Bitcoin Core").locator(".badge")).toHaveText("Connected");
        const snapshot = bitcoin.state.snapshot;
        expect(await cardValues(page, "Bitcoin Core")).toEqual({
          Network: snapshot.network,
          "Block height": snapshot.block_height.toLocaleString("en-US"),
          "Header height": snapshot.header_height.toLocaleString("en-US"),
          Synchronized: snapshot.synchronized ? "Yes" : "No",
        });
        await expect(card(page, "LND").locator(".badge")).toHaveText("Connected");
        const node = lightning.state.snapshot;
        expect(await cardValues(page, "LND")).toEqual({
          "Node ID": node.node_id,
          "Synced to chain": node.synced_to_chain ? "Yes" : "No",
          "Active channels": String(node.active_channels),
          "Inactive channels": String(node.inactive_channels),
        });
        await expect(card(page, "BTCPay Server").locator(".badge")).toHaveText("Not observed");
        expect(await cardValues(page, "Rieko")).not.toHaveProperty("Channel data source");
        for (const name of SERVICES) await expect(card(page, name)).not.toContainText("Healthy");
      }, undefined, false, await sourceArgs(info, { core: core.url, lnd: lnd.url }));
    } finally {
      await core.stop();
      await lnd.stop();
    }
  });

  test("a connected BTCPay Greenfield source shows its poll times", async ({ page }, info) => {
    const btcpay = await mockBtcPay();
    try {
      await withAgent("embedded", info, async url => {
        const inspection = await waitFor(url, "/inspect/btcpay", body => body.state?.source?.BtcPayGreenfield?.connected === true);
        await page.goto(url);
        await expect(card(page, "BTCPay Server").locator(".badge")).toHaveText("Connected");
        const values = await cardValues(page, "BTCPay Server");
        expect(Object.keys(values)).toEqual(["Last successful poll", "Last attempt", "Data as of"]);
        // Formatted in the page, so the expectation uses the browser's locale.
        const expected = await page.evaluate(iso => new Date(iso).toLocaleString(), inspection.state.last_success);
        expect(values["Last successful poll"]).toContain(expected);
      }, undefined, false, await sourceArgs(info, { btcpay: btcpay.url }));
    } finally {
      await btcpay.stop();
    }
  });

  test("a Core outage changes only the Core card and keeps last known values", async ({ page }, info) => {
    const core = await mockCore();
    const lnd = await mockLnd();
    try {
      await withAgent("embedded", info, async url => {
        await waitFor(url, "/inspect/bitcoin", body => body.state?.connected === true);
        await waitFor(url, "/inspect/lightning", body => body.state?.connected === true);
        await page.goto(url);
        await expect(card(page, "Bitcoin Core").locator(".badge")).toHaveText("Connected");
        const before = await cardValues(page, "Bitcoin Core");
        await core.stop();
        await waitFor(url, "/inspect/bitcoin", body => body.state?.connected === false);
        await page.reload();
        await expect(card(page, "Bitcoin Core").locator(".badge")).toHaveText("Disconnected");
        await expect(card(page, "Bitcoin Core")).toContainText("Last known values");
        expect(await cardValues(page, "Bitcoin Core")).toEqual(before);
        await expect(card(page, "LND").locator(".badge")).toHaveText("Connected");
      }, undefined, false, await sourceArgs(info, { core: core.url, lnd: lnd.url }));
    } finally {
      await core.stop();
      await lnd.stop();
    }
  });

  test("an unreachable Core is never connected and shows only its attempt", async ({ page }, info) => {
    const unreachable = `http://127.0.0.1:${await freePort()}`;
    await withAgent("embedded", info, async url => {
      await waitFor(url, "/inspect/bitcoin", body => body.state !== null && body.state.connected === false);
      await page.goto(url);
      await expect(card(page, "Bitcoin Core").locator(".badge")).toHaveText("Never connected");
      await expect(card(page, "Bitcoin Core").getByRole("definition")).toHaveCount(0);
      await expect(card(page, "Bitcoin Core")).toContainText("Last attempt");
    }, undefined, false, await sourceArgs(info, { core: unreachable }));
  });

  test("one failing endpoint affects only its own card", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.route(`${url}/inspect/lightning`, route => route.fulfill({ status: 500, body: "synthetic failure" }));
      await page.goto(url);
      // Non-authentication errors keep the client's default three retries.
      await expect(card(page, "LND")).toContainText("Unavailable: 500", { timeout: 15_000 });
      await expect(card(page, "Bitcoin Core").locator(".badge")).toHaveText("Not observed");
      await expect(card(page, "Rieko").getByRole("definition").first()).toBeVisible();
    });
  });

  // Review findings F1 and F2: a request that fails after a successful load must
  // not leave the earlier answer on screen as if it were current.
  test("a failing /status after a good load makes the pill and Rieko card unavailable", async ({ page }, info) => {
    test.setTimeout(60_000);
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      const pill = page.getByRole("link", { name: /^Rieko pipeline:/ });
      await expect(pill).toHaveText(/^Rieko pipeline: (Healthy|Degraded|Unhealthy|Not initialized)$/);
      await page.route(`${url}/status`, route => route.abort("connectionrefused"));
      // Remounting the Overview refetches; the pill shares the same query.
      await page.getByRole("link", { name: "Findings", exact: true }).click();
      await page.getByRole("link", { name: "Overview", exact: true }).click();
      await expect(card(page, "Rieko")).toContainText("Unavailable", { timeout: 30_000 });
      await expect(pill).toHaveText("Rieko pipeline: unavailable");
    });
  });

  test("a failing findings request after a good load removes the Rieko card's count", async ({ page }, info) => {
    test.setTimeout(60_000);
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      await expect(page.getByRole("region", { name: "Active findings", exact: true }).getByRole("listitem").first()).toBeVisible();
      expect(await cardValues(page, "Rieko")).toHaveProperty("Active findings");
      await page.route(url => url.pathname === "/findings", route => route.fulfill({ status: 500, body: "synthetic failure" }));
      await page.getByRole("link", { name: "Findings", exact: true }).click();
      await page.getByRole("link", { name: "Overview", exact: true }).click();
      await expect(page.getByRole("region", { name: "Active findings", exact: true })).toContainText("Unavailable: 500", { timeout: 30_000 });
      expect(await cardValues(page, "Rieko")).not.toHaveProperty("Active findings");
    }, undefined, true);
  });

  test("seeded active findings match the API and link to Findings", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      const findingsResponse = page.waitForResponse(response =>
        new URL(response.url()).pathname === "/findings" && new URL(response.url()).searchParams.get("lifecycle") === "active");
      await page.goto(url);
      const findings = await (await findingsResponse).json();
      expect(findings.length).toBeGreaterThan(0);
      const panel = page.getByRole("region", { name: "Active findings", exact: true });
      await expect(panel.getByRole("listitem")).toHaveCount(findings.length);
      await expect(panel.locator(".count")).toHaveText(`${findings.length} active findings`);
      await expect(panel.locator(".count .visually-hidden")).toHaveText(" active findings");
      await expect(panel.getByRole("listitem").locator(".tag")).toHaveText(findings.map((finding: { severity: string }) => finding.severity));
      expect((await cardValues(page, "Rieko"))["Active findings"]).toBe(String(findings.length));
      await panel.getByRole("link", { name: "View all findings", exact: true }).click();
      await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();
    }, undefined, true);
  });

  test("while the token prompt is shown there is no pill and no Overview request", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      // Before the first 401 the UI does not yet know a token is required, so
      // only requests made after the prompt appears are counted.
      await page.goto(url);
      await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
      const paths: string[] = [];
      page.on("request", request => paths.push(new URL(request.url()).pathname));
      await page.waitForTimeout(1000);
      expect(paths.filter(path => path.startsWith("/inspect") || path === "/findings")).toEqual([]);
      await expect(page.getByRole("link", { name: /^Rieko pipeline:/ })).toHaveCount(0);
      await unlock(page);
      await expect(page.getByRole("link", { name: /^Rieko pipeline:/ })).toBeVisible();
      await expect(card(page, "Bitcoin Core").locator(".badge")).toHaveText("Not observed");
    }, "synthetic-browser-token");
  });

  test("readable and without overflow in both themes at every width, with all sources and findings", async ({ page }, info) => {
    const [core, lnd, btcpay] = await Promise.all([mockCore(), mockLnd(), mockBtcPay()]);
    try {
      await withAgent("embedded", info, async url => {
        await waitFor(url, "/inspect/btcpay", body => body.state?.source?.BtcPayGreenfield?.connected === true);
        await waitFor(url, "/inspect/lightning", body => body.state?.connected === true);
        await waitFor(url, "/inspect/bitcoin", body => body.state?.connected === true);
        for (const theme of ["dark", "light"] as const) {
          for (const width of WIDTHS) {
            await page.setViewportSize({ width, height: 900 });
            await page.goto(`${url}/#/overview`);
            await useTheme(page, theme);
            for (const name of SERVICES) await expect(card(page, name).locator(".badge")).toHaveText("Connected");
            await expect(page.getByRole("region", { name: "Active findings", exact: true }).getByRole("listitem").first()).toBeVisible();
            await expectReadable(page, `${theme} ${width}px overview`);
            const overflow = await page.evaluate(() => {
              const main = document.querySelector("main")!;
              return {
                page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
                main: main.scrollWidth - main.clientWidth,
              };
            });
            expect(overflow, `${theme} ${width}px`).toEqual({ page: 0, main: 0 });
          }
        }
      }, undefined, true, await sourceArgs(info, { core: core.url, lnd: lnd.url, btcpay: btcpay.url }));
    } finally {
      await Promise.all([core.stop(), lnd.stop(), btcpay.stop()]);
    }
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
        const rieko = await cardValues(page, "Rieko");
        expect(rieko.Version).toBe(`v${status.version}`);
        expect(rieko.Schema).toBe(String(status.schema_version));
        expect(rieko["Database integrity"]).toBe(status.integrity);
        expect(rieko["Findings (all)"]).toBe(String(status.counts.findings));
        await expect(health.getByRole("region", { name: "Rieko", exact: true }).locator(".badge")).toHaveText(`Pipeline: ${PIPELINE[status.overall]}`);
        await expect(page.getByRole("link", { name: /^Rieko pipeline:/ })).toHaveText(`Rieko pipeline: ${PIPELINE[status.overall]}`);
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

// ─── Findings and Services (MS-2.3c) ───

/** Captures the next GET to `path` (optionally with matching query parameters). */
function nextGet(page: Page, path: string, params: Record<string, string> = {}) {
  return page.waitForResponse(response => {
    const url = new URL(response.url());
    return response.request().method() === "GET" && url.pathname === path
      && Object.entries(params).every(([key, value]) => url.searchParams.get(key) === value);
  });
}

const findingRows = (page: Page) => page.getByRole("table", { name: "Findings", exact: true }).locator("tbody tr");

test.describe("Findings and Services", () => {
  test("the lifecycle filter requests and shows exactly the chosen findings, Active by default", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      const active = nextGet(page, "/findings", { lifecycle: "active", limit: "200" });
      await page.goto(`${url}/#/findings`);
      const activeBody = await (await active).json();
      const group = page.getByRole("group", { name: "Lifecycle", exact: true });
      await expect(group.getByRole("button", { name: "Active", exact: true })).toHaveAttribute("aria-pressed", "true");
      await expect(findingRows(page)).toHaveCount(activeBody.length);
      expect(await findingRows(page).getByRole("link").evaluateAll(links => links.map(link => link.getAttribute("href"))))
        .toEqual(activeBody.map((finding: { id: string }) => `#/findings/${encodeURIComponent(finding.id)}`));
      await expect(page.getByRole("columnheader", { name: "Ratio" })).toHaveCount(0);

      const resolved = nextGet(page, "/findings", { lifecycle: "resolved" });
      await group.getByRole("button", { name: "Resolved", exact: true }).click();
      const resolvedBody = await (await resolved).json();
      await expect(group.getByRole("button", { name: "Resolved", exact: true })).toHaveAttribute("aria-pressed", "true");
      // The seed has no resolved findings; this checks the empty state truthfully.
      expect(resolvedBody).toEqual([]);
      await expect(page.locator("main")).toContainText("No resolved findings.");

      const all = nextGet(page, "/findings", { lifecycle: "all" });
      await group.getByRole("button", { name: "All", exact: true }).click();
      const allBody = await (await all).json();
      await expect(findingRows(page)).toHaveCount(allBody.length);
      expect(await findingRows(page).getByRole("link").evaluateAll(links => links.map(link => link.getAttribute("href"))))
        .toEqual(allBody.map((finding: { id: string }) => `#/findings/${encodeURIComponent(finding.id)}`));
    }, undefined, true);
  });

  test("finding detail shows exactly the stored evidence, provenance and linked recommendations", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(`${url}/#/findings`);
      await expect(findingRows(page).first()).toBeVisible();
      const link = findingRows(page).first().getByRole("link");
      const id = decodeURIComponent((await link.getAttribute("href"))!.replace("#/findings/", ""));
      const detail = nextGet(page, `/findings/${id}`);
      const recommendations = nextGet(page, "/recommendations", { lifecycle: "all", limit: "500" });
      await link.focus();
      await page.keyboard.press("Enter");
      const finding = await (await detail).json();
      const linked = (await (await recommendations).json()).filter((rec: { finding_id: string }) => rec.finding_id === id);
      expect(new URL(page.url()).hash).toBe(`#/findings/${encodeURIComponent(id)}`);
      await expect(page.getByRole("heading", { level: 2 })).toBeFocused();
      await expect(page.locator("nav a[aria-current=page]")).toHaveText(["Findings"]);

      const section = (name: string) => page.getByRole("region", { name, exact: true });
      const pairs = async (name: string) => {
        const terms = await section(name).getByRole("term").allTextContents();
        const values = await section(name).getByRole("definition").allTextContents();
        return Object.fromEntries(terms.map((term, index) => [term.trim(), values[index].trim()]));
      };
      const evidence = await pairs("Evidence");
      expect(Object.keys(evidence)).toEqual(finding.evidence.map((item: { key: string }) => item.key));
      for (const item of finding.evidence) {
        const expected = item.value !== null && typeof item.value === "object" ? JSON.stringify(item.value, null, 2) : String(item.value);
        expect(evidence[item.key]).toBe(expected);
      }
      const summary = await pairs("Summary");
      expect(summary).toMatchObject({ Severity: finding.severity, State: finding.lifecycle, Detector: `${finding.detector} v${finding.detector_version}` });
      expect(finding.provenance.source.kind).toBe("fixture");
      expect(await pairs("Provenance")).toMatchObject({
        Network: finding.provenance.network, Source: "Fixture", "Content hash": finding.provenance.source.redacted_hash,
      });
      const producers = section("Provenance").getByRole("table", { name: "Producers", exact: true }).locator("tbody tr");
      await expect(producers).toHaveCount(finding.provenance.producers.length);
      for (const [index, producer] of finding.provenance.producers.entries()) {
        await expect(producers.nth(index).getByRole("cell")).toHaveText([producer.name, producer.version, producer.role]);
      }
      await expect(section("Provenance")).toContainText(finding.provenance.observation.snapshot.state_digest);

      const items = section("Recommendations").getByRole("listitem").filter({ has: page.getByRole("heading", { level: 4 }) });
      expect(linked.length).toBeGreaterThan(0);
      await expect(items).toHaveCount(linked.length);
      for (const [index, rec] of linked.entries()) {
        await expect(items.nth(index).getByRole("heading", { level: 4 })).toHaveText(rec.action.summary);
        await expect(items.nth(index)).toContainText(rec.rationale.expected_effect);
        await expect(items.nth(index).getByRole("definition")).toHaveText([
          rec.action.action_type, rec.action.stage, rec.lifecycle ?? "active",
          rec.rationale.actionability === "OperatorActionable" ? "Operator may choose to act" : rec.rationale.actionability,
        ]);
        await expect(items.nth(index).getByRole("listitem")).toHaveText([
          ...rec.rationale.evidence, ...rec.rationale.preconditions, ...rec.rationale.risks, ...rec.rationale.limitations,
        ]);
      }
      await expect(section("Recommendations")).not.toContainText("may be incomplete");
      await page.getByRole("link", { name: "Back to findings", exact: true }).click();
      await expect(findingRows(page).first()).toBeVisible();
      await page.goBack();
      await expect(section("Evidence")).toBeVisible();
      await expect(page.getByRole("heading", { level: 2 })).toBeFocused();
      await page.goForward();
      await expect(findingRows(page).first()).toBeVisible();
    }, undefined, true);
  });

  test("Overview findings open their detail page", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      const panel = page.getByRole("region", { name: "Active findings", exact: true });
      const first = panel.getByRole("link", { name: /^View details for / }).first();
      await expect(first).toBeVisible();
      await first.click();
      await expect(page).toHaveURL(/#\/findings\/finding-/);
      await expect(page.getByRole("region", { name: "Evidence", exact: true })).toBeVisible();
    }, undefined, true);
  });

  test("missing provenance is stated, not implied (labelled test double)", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      const findings = await (await fetch(`${url}/findings?lifecycle=active`)).json();
      const id = findings[0].id;
      // Test double: the real response with provenance removed, as agent-raised
      // findings are stored. Producing one for real needs a signed webhook flow.
      await page.route(`${url}/findings/${id}`, async route => {
        const response = await route.fetch();
        await route.fulfill({ response, json: { ...(await response.json()), provenance: null } });
      });
      await page.goto(`${url}/#/findings/${encodeURIComponent(id)}`);
      const provenance = page.getByRole("region", { name: "Provenance", exact: true });
      await expect(provenance).toContainText("No provenance is recorded for this finding.");
      await expect(provenance.getByRole("definition")).toHaveCount(0);
    }, undefined, true);
  });

  test("an unknown finding is reported as not found without retries", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      let requests = 0;
      page.on("request", request => { if (new URL(request.url()).pathname === "/findings/finding-does-not-exist") requests++; });
      await page.goto(`${url}/#/findings/finding-does-not-exist`);
      await expect(page.locator("main")).toContainText("Finding not found.", { timeout: 3_000 });
      expect(requests).toBe(1);
    });
  });

  test("Services shows the service cards and channels, and the old Channels address still works", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(`${url}/#/channels`);
      await expect(page.getByRole("heading", { name: "Services", exact: true })).toBeVisible();
      await expect(page.locator("nav a[aria-current=page]")).toHaveText(["Services"]);
      const services = page.getByRole("region", { name: "Service status", exact: true });
      for (const name of SERVICES) {
        await expect(services.getByRole("region", { name, exact: true }).locator(".badge")).toHaveText("Not observed");
      }
      await expect(page.getByRole("heading", { name: "Channel liquidity", exact: true })).toBeVisible();
      await expect(page.locator("main tbody tr").first()).toBeVisible();
      await expect(page.getByRole("link", { name: "Channels", exact: true })).toHaveCount(0);
    }, undefined, true);
  });

  test("the sidebar count equals the active findings and keeps the link name", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      const active = nextGet(page, "/findings", { lifecycle: "active" });
      await page.goto(url);
      const findings = await (await active).json();
      const link = page.getByRole("link", { name: "Findings", exact: true });
      await expect(link).toHaveAccessibleDescription(`${findings.length} active findings`);
      await expect(page.locator("aside .nav-count")).toHaveText(String(findings.length));
    }, undefined, true);
  });

  test("the sidebar reports zero active findings on an empty database", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      const active = nextGet(page, "/findings", { lifecycle: "active", limit: "50" });
      await page.goto(url);
      expect(await (await active).json()).toEqual([]);
      await expect(page.getByRole("link", { name: "Findings", exact: true })).toHaveAccessibleDescription("0 active findings");
      await expect(page.locator("aside .nav-count")).toHaveText("0");
    });
  });

  test("large structured evidence and the recommendation limit are explicit (labelled test doubles)", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      const findings = await (await fetch(`${url}/findings?lifecycle=active`)).json();
      const id = findings[0].id;
      const value = { invoice_ids: Array.from({ length: 80 }, (_, index) => `${index}-${"x".repeat(100)}`) };
      await page.route(`${url}/findings/${id}`, async route => {
        const response = await route.fetch();
        const finding = await response.json();
        await route.fulfill({ response, json: { ...finding, evidence: [{ key: "structured", value }] } });
      });
      await page.route(`${url}/recommendations?lifecycle=all&limit=500`, async route => {
        const response = await route.fetch();
        const [rec] = await response.json();
        await route.fulfill({ response, json: Array.from({ length: 500 }, (_, index) => ({
          ...rec, finding_id: index === 0 ? id : "unrelated-finding", action: { ...rec.action, id: `test-${index}` },
        })) });
      });
      await page.setViewportSize({ width: 390, height: 900 });
      await page.goto(`${url}/#/findings/${encodeURIComponent(id)}`);
      const evidence = page.getByRole("region", { name: "Evidence", exact: true });
      await expect(evidence.getByRole("definition")).toHaveText(JSON.stringify(value, null, 2));
      const recommendations = page.getByRole("region", { name: "Recommendations", exact: true });
      await expect(recommendations).toContainText("Only the latest 500 recommendations were checked, so this list may be incomplete.");
      await expect(recommendations.getByRole("heading", { level: 4 })).toHaveCount(1);
      expect(await page.evaluate(() => {
        const main = document.querySelector("main")!;
        return [document.documentElement.scrollWidth - document.documentElement.clientWidth, main.scrollWidth - main.clientWidth];
      })).toEqual([0, 0]);
    }, undefined, true);
  });

  test("detail loading and failure are visible without rendering a summary (labelled test double)", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      let release!: () => void;
      const held = new Promise<void>(done => { release = done; });
      await page.route(`${url}/findings/finding-unavailable`, async route => {
        await held;
        await route.fulfill({ status: 503, body: "synthetic service failure" });
      });
      try {
        await page.goto(`${url}/#/findings/finding-unavailable`);
        await expect(page.locator("main")).toContainText("Loading…");
        await expect(page.getByRole("region", { name: "Summary", exact: true })).toHaveCount(0);
        release();
        await expect(page.locator("main").getByRole("alert")).toContainText("Unavailable: 503 synthetic service failure", { timeout: 15_000 });
        await expect(page.getByRole("region", { name: "Summary", exact: true })).toHaveCount(0);
      } finally { release(); }
    });
  });

  test("no sidebar count while the token prompt is shown", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      await page.goto(url);
      await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
      await expect(page.locator("aside .nav-count")).toHaveCount(0);
      const active = nextGet(page, "/findings", { lifecycle: "active", limit: "50" });
      await unlock(page);
      const findings = await (await active).json();
      expect(findings.length).toBeGreaterThan(0);
      await expect(page.locator("aside .nav-count")).toHaveText(String(findings.length));
      await page.getByRole("button", { name: "Forget token", exact: true }).click();
      await expect(page.getByLabel("API token", { exact: true })).toBeVisible();
      await expect(page.locator("aside .nav-count")).toHaveCount(0);
    }, "synthetic-browser-token", true);
  });

  test("list, detail and Services are readable without overflow in both themes at every width", async ({ page }, info) => {
    test.setTimeout(90_000);
    await withAgent("embedded", info, async url => {
      const findings = await (await fetch(`${url}/findings?lifecycle=active`)).json();
      const detail = `#/findings/${encodeURIComponent(findings[0].id)}`;
      for (const theme of ["dark", "light"] as const) {
        for (const width of WIDTHS) {
          await page.setViewportSize({ width, height: 900 });
          for (const [hash, ready, mainMayScroll] of [
            ["#/findings", () => findingRows(page).first(), false],
            [detail, () => page.getByRole("region", { name: "Evidence", exact: true }).getByRole("term").first(), false],
            ["#/services", () => page.locator("main tbody tr").first(), true],
          ] as const) {
            await page.goto(`${url}/${hash}`);
            await useTheme(page, theme);
            await expect(ready()).toBeVisible();
            await expectReadable(page, `${theme} ${width}px ${hash}`);
            const overflow = await page.evaluate(() => {
              const main = document.querySelector("main")!;
              return {
                page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
                main: main.scrollWidth - main.clientWidth,
              };
            });
            expect(overflow.page, `${theme} ${width}px ${hash} page`).toBe(0);
            // The unchanged channel table may scroll inside the content area (review note m4).
            if (!mainMayScroll) expect(overflow.main, `${theme} ${width}px ${hash} main`).toBe(0);
            await page.screenshot({ path: info.outputPath(`${hash === detail ? "detail" : hash.slice(2)}-${theme}-${width}.png`), fullPage: true });
            if (hash === "#/findings" && width === 390) {
              const table = page.getByRole("region", { name: "Findings table", exact: true });
              await table.focus();
              await expect(table).toBeFocused();
              await page.keyboard.press("ArrowRight");
              await expect.poll(() => table.evaluate(element => element.scrollLeft)).toBeGreaterThan(0);
            }
          }
        }
      }
    }, undefined, true);
  });
});

// DC3: the Create simulation dialog belongs to Recommendations.
const simulationDialog = (page: Page) => page.getByRole("dialog", { name: "Create simulation", exact: true });
const channelChoices = (select: import("@playwright/test").Locator) =>
  select.locator("option").evaluateAll(options => options.map(option => (option as HTMLOptionElement).value));

test.describe("DC3 simulation dialog", () => {
  test("a cold dialog gains the real channel choices when delayed snapshots arrive", async ({ page }, info) => {
    await withAgent("embedded", info, async url => {
      let release!: () => void;
      const held = new Promise<void>(done => { release = done; });
      await page.route(`${url}/snapshots?limit=500`, async route => {
        const response = await route.fetch();
        await held;
        await route.fulfill({ response });
      });
      try {
        const snapshotsResponse = nextGet(page, "/snapshots", { limit: "500" });
        const recommendationsResponse = nextGet(page, "/recommendations", { limit: "100" });
        await page.goto(`${url}/#/recommendations`);
        const recommendations = await (await recommendationsResponse).json();
        await page.getByRole("button", { name: "Simulate", exact: true }).first().click();
        const dialog = simulationDialog(page);
        const source = dialog.getByLabel("Source channel", { exact: true });
        const destination = dialog.getByLabel("Destination channel", { exact: true });
        await expect(source.locator("option")).toHaveCount(1);
        await expect(destination.locator("option")).toHaveCount(1);
        await expect(source).toHaveValue("");
        await expect(destination).toHaveValue("");
        release();
        const snapshots = await (await snapshotsResponse).json();
        const ids = [...new Set<string>(snapshots.map((snapshot: { channel_id: string }) => snapshot.channel_id))].sort();
        expect(ids.length).toBeGreaterThanOrEqual(2);
        await expect.poll(() => channelChoices(source)).toEqual(["", ...ids]);
        await expect.poll(() => channelChoices(destination)).toEqual(["", ...ids]);
        await expect(source).toHaveValue("");
        await expect(destination).toHaveValue("");
        await source.selectOption(ids[0]);
        await destination.selectOption(ids[1]);
        await dialog.getByLabel("Amount in sats", { exact: true }).fill("1000");
        const submitted = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v2/simulations" && response.request().method() === "POST");
        await dialog.getByRole("button", { name: "Run simulation", exact: true }).click();
        const response = await submitted;
        expect(response.request().postDataJSON()).toEqual({
          recommendation_id: recommendations[0].action.id, model_id: "liquidity-redistribution",
          source_channel: ids[0], destination_channel: ids[1], amount_sats: 1000, allow_stale: false,
        });
        // The real fixture is refused (stale or missing spendable reserves), as
        // documented by the standing smoke test. This does not claim success.
        expect([400, 409]).toContain(response.status());
        expect(["invalid_input", "stale_input"]).toContain((await response.json()).error.code);
        await expect(dialog.getByRole("alert")).toContainText(String(response.status()));
      } finally { release(); }
    }, undefined, true);
  });

  test("a later snapshot poll updates choices once and retains selections (labelled response double)", async ({ page }, info) => {
    test.setTimeout(45_000);
    await withAgent("embedded", info, async url => {
      const snapshots = await (await fetch(`${url}/snapshots?limit=500`)).json();
      const ids = [...new Set<string>(snapshots.map((snapshot: { channel_id: string }) => snapshot.channel_id))].sort();
      let update = false;
      let updatesDelivered = 0;
      await page.route(`${url}/snapshots?limit=500`, async route => {
        if (!update) { await route.continue(); return; }
        const response = await route.fetch();
        // Deliberately labelled double: add one channel and repeat an existing
        // observation, in unsorted order, on the real 15-second polling request.
        await route.fulfill({ response, json: [
          { ...snapshots[0], channel_id: "dc3-added-channel" }, ...snapshots, snapshots[0],
        ] });
        updatesDelivered++;
      });
      await page.goto(`${url}/#/services`);
      await expect(page.locator("main tbody tr").first()).toBeVisible();
      await page.getByRole("link", { name: "Recommendations", exact: true }).click();
      await page.getByRole("button", { name: "Simulate", exact: true }).first().click();
      const dialog = simulationDialog(page);
      const source = dialog.getByLabel("Source channel", { exact: true });
      const destination = dialog.getByLabel("Destination channel", { exact: true });
      await expect.poll(() => channelChoices(source)).toEqual(["", ...ids]);
      await source.selectOption(ids[0]);
      await destination.selectOption(ids[1]);
      update = true;
      await expect.poll(() => updatesDelivered, { timeout: 25_000 }).toBeGreaterThan(0);
      const expected = ["", ...[...ids, "dc3-added-channel"].sort()];
      await expect.poll(() => channelChoices(source)).toEqual(expected);
      await expect.poll(() => channelChoices(destination)).toEqual(expected);
      await expect(source).toHaveValue(ids[0]);
      await expect(destination).toHaveValue(ids[1]);
    }, undefined, true);
  });

  test("the full real refusal wraps inside the dialog in both themes at every width", async ({ page }, info) => {
    test.setTimeout(60_000);
    await withAgent("embedded", info, async url => {
      // Warm the real snapshot cache to isolate layout from the cold-load case.
      await page.goto(`${url}/#/services`);
      await expect(page.locator("main tbody tr").first()).toBeVisible();
      await page.getByRole("link", { name: "Recommendations", exact: true }).click();
      await expect(page.getByRole("button", { name: "Simulate", exact: true }).first()).toBeVisible();
      const measurements: { theme: string; width: number; error: number; card: number }[] = [];
      for (const theme of ["dark", "light"] as const) {
        await useTheme(page, theme);
        await page.getByRole("button", { name: "Simulate", exact: true }).first().click();
        const dialog = simulationDialog(page);
        const source = dialog.getByLabel("Source channel", { exact: true });
        const ids = (await channelChoices(source)).filter(Boolean);
        expect(ids.length).toBeGreaterThanOrEqual(2);
        await source.selectOption(ids[0]);
        await dialog.getByLabel("Destination channel", { exact: true }).selectOption(ids[1]);
        await dialog.getByLabel("Amount in sats", { exact: true }).fill("1000");
        const submitted = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v2/simulations" && response.request().method() === "POST");
        await dialog.getByRole("button", { name: "Run simulation", exact: true }).click();
        const response = await submitted;
        expect([400, 409]).toContain(response.status());
        const body = await response.text();
        expect(["invalid_input", "stale_input"]).toContain(JSON.parse(body).error.code);
        const alert = dialog.getByRole("alert");
        await expect(alert).toHaveText(`${response.status()} ${body}`);
        for (const width of WIDTHS) {
          await page.setViewportSize({ width, height: 900 });
          await expectReadable(page, `${theme} ${width}px simulation refusal`);
          const measured = await alert.evaluate(element => {
            const card = element.closest(".overlay-card")!;
            return { error: element.scrollWidth - element.clientWidth, card: card.scrollWidth - card.clientWidth };
          });
          measurements.push({ theme, width, ...measured });
          await alert.scrollIntoViewIfNeeded();
          await page.screenshot({ path: info.outputPath(`refusal-${theme}-${width}.png`), fullPage: true });
          for (const name of ["Run simulation", "Cancel"]) {
            const button = dialog.getByRole("button", { name, exact: true });
            await button.scrollIntoViewIfNeeded();
            await expect(button).toBeInViewport({ ratio: 1 });
          }
        }
        await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
      }
      await writeFile(info.outputPath("refusal-measurements.json"), JSON.stringify(measurements, null, 2));
      expect(measurements).toEqual(measurements.map(item => ({ ...item, error: 0, card: 0 })));
    }, undefined, true);
  });
});
