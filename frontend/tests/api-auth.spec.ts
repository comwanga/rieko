import { expect, test } from "@playwright/test";
import { get as storeValue } from "svelte/store";
import { authenticate, get, post, setupApiBase } from "../src/lib/api";
import {
  AuthenticationError, CredentialsChangedError, TOKEN_STORAGE_KEY,
  authState, credentialSnapshot, forgetToken, initializeAuth,
} from "../src/lib/auth";

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
const originalFetch = globalThis.fetch;
let values: Map<string, string>;
let failures: { read: boolean; write: boolean; remove: boolean };

test.beforeEach(() => {
  values = new Map();
  failures = { read: false, write: false, remove: false };
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    location: new URL("http://rieko.test/"),
    sessionStorage: {
      getItem(key: string) { if (failures.read) throw new Error("blocked"); return values.get(key) ?? null; },
      setItem(key: string, value: string) { if (failures.write) throw new Error("blocked"); values.set(key, value); },
      removeItem(key: string) { if (failures.remove) throw new Error("blocked"); values.delete(key); },
    },
  } });
  setupApiBase("");
  initializeAuth();
  globalThis.fetch = async () => Response.json({ ok: true });
});

test.afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

test("restored credentials cover both verbs and same-origin path prefixes", async () => {
  values.set(TOKEN_STORAGE_KEY, "synthetic-restored");
  initializeAuth();
  setupApiBase("/prefix/");
  const calls: { url: string; init: RequestInit }[] = [];
  globalThis.fetch = async (url, init) => { calls.push({ url: String(url), init: init! }); return Response.json({ ok: true }); };
  await get("/status");
  await post("/api/v2/simulations", { amount_sats: 1 });
  expect(calls.map(call => call.url)).toEqual(["http://rieko.test/prefix/status", "http://rieko.test/prefix/api/v2/simulations"]);
  for (const call of calls) expect(new Headers(call.init.headers).get("Authorization")).toBe("Bearer synthetic-restored");
  expect(new Headers(calls[1].init.headers).get("Content-Type")).toBe("application/json");
  expect(calls[1].init.body).toBe(JSON.stringify({ amount_sats: 1 }));
  expect(JSON.stringify(storeValue(authState))).not.toContain("synthetic-restored");
});

test("tokenless requests remain tokenless", async () => {
  globalThis.fetch = async (_url, init) => {
    expect(new Headers(init?.headers).has("Authorization")).toBe(false);
    return Response.json({ ok: true });
  };
  await get("/status");
  expect(values.size).toBe(0);
});

test("validation trims and persists only after a successful read-only probe", async () => {
  globalThis.fetch = async (url, init) => {
    expect(String(url)).toBe("http://rieko.test/status");
    expect(init?.method).toBe("GET");
    expect(values.has(TOKEN_STORAGE_KEY)).toBe(false);
    expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer synthetic-valid");
    return Response.json({ ok: true });
  };
  await authenticate("  synthetic-valid  ");
  expect(values.get(TOKEN_STORAGE_KEY)).toBe("synthetic-valid");
  expect(credentialSnapshot().token).toBe("synthetic-valid");
});

test("empty, wrong and unreachable validation do not replace a working token", async () => {
  values.set(TOKEN_STORAGE_KEY, "synthetic-working");
  initializeAuth();
  let calls = 0;
  globalThis.fetch = async () => { calls++; return new Response("do not echo server auth errors", { status: 401 }); };
  await expect(authenticate(" \n ")).rejects.toThrow("Enter an API token");
  expect(calls).toBe(0);
  await expect(authenticate("synthetic-wrong")).rejects.toThrow("Token not accepted");
  expect(calls).toBe(1);
  globalThis.fetch = async () => { throw new TypeError("offline"); };
  await expect(authenticate("synthetic-candidate")).rejects.toThrow("offline");
  expect(credentialSnapshot().token).toBe("synthetic-working");
  expect(values.get(TOKEN_STORAGE_KEY)).toBe("synthetic-working");
  expect(storeValue(authState).required).toBe(false);
});

test("401 clears only our key and never replays a POST after login", async () => {
  values.set(TOKEN_STORAGE_KEY, "synthetic-old");
  values.set("other-app", "keep");
  initializeAuth();
  const methods: string[] = [];
  globalThis.fetch = async (_url, init) => {
    methods.push(init!.method!);
    return methods.length === 1 ? new Response("unauthorized", { status: 401 }) : Response.json({ ok: true });
  };
  await expect(post("/api/v2/simulations", { amount_sats: 1 })).rejects.toBeInstanceOf(AuthenticationError);
  expect(methods).toEqual(["POST"]);
  expect(storeValue(authState).required).toBe(true);
  expect(credentialSnapshot().token).toBeUndefined();
  expect(values.has(TOKEN_STORAGE_KEY)).toBe(false);
  expect(values.get("other-app")).toBe("keep");
  await authenticate("synthetic-new");
  expect(methods).toEqual(["POST", "GET"]);
});

test("credentials are refused for normalized cross-origin destinations", async () => {
  await authenticate("synthetic-valid");
  let calls = 0;
  globalThis.fetch = async () => { calls++; return Response.json({}); };
  for (const base of ["https://other.test", "//other.test", "http://rieko.test:1234"]) {
    setupApiBase(base);
    await expect(get("/status")).rejects.toThrow("only be sent");
    await expect(post("/write", {})).rejects.toThrow("only be sent");
    await expect(authenticate("synthetic-candidate")).rejects.toThrow("only be sent");
  }
  expect(calls).toBe(0);
});

test("blocked storage reads and writes permit memory-only operation", async () => {
  failures.read = failures.write = true;
  initializeAuth();
  await authenticate("synthetic-memory");
  expect(credentialSnapshot().token).toBe("synthetic-memory");
  expect(storeValue(authState).storage).toBe("memory");
  expect(values.size).toBe(0);
  await get("/status");
});

test("failed storage removal clears this page and reports the saved value may remain", async () => {
  await authenticate("synthetic-saved");
  values.set("other-app", "keep");
  failures.remove = true;
  forgetToken();
  expect(credentialSnapshot().token).toBeUndefined();
  expect(storeValue(authState).hasToken).toBe(false);
  expect(storeValue(authState).storage).toBe("clear-failed");
  expect(values.get(TOKEN_STORAGE_KEY)).toBe("synthetic-saved");
  failures.remove = false;
  forgetToken();
  expect(values.has(TOKEN_STORAGE_KEY)).toBe(false);
  expect(values.get("other-app")).toBe("keep");
});

for (const status of [200, 401]) {
  test(`stale ${status} cannot return data or invalidate a newer credential`, async () => {
    await authenticate("synthetic-old");
    const delayed = deferred<Response>();
    globalThis.fetch = async () => delayed.promise;
    const old = get("/findings");
    globalThis.fetch = async () => Response.json({});
    await authenticate("synthetic-new");
    delayed.resolve(Response.json({ secret: "old-data" }, { status }));
    await expect(old).rejects.toBeInstanceOf(CredentialsChangedError);
    expect(credentialSnapshot().token).toBe("synthetic-new");
    expect(storeValue(authState).required).toBe(false);
  });
  test(`delayed validation ${status} cannot undo Forget or replace newer login`, async () => {
    const delayed = deferred<Response>();
    globalThis.fetch = async () => delayed.promise;
    const old = authenticate("synthetic-candidate");
    forgetToken();
    if (status === 401) {
      globalThis.fetch = async () => Response.json({});
      await authenticate("synthetic-new");
    }
    delayed.resolve(Response.json({}, { status }));
    await expect(old).rejects.toBeInstanceOf(CredentialsChangedError);
    expect(credentialSnapshot().token).toBe(status === 401 ? "synthetic-new" : undefined);
    expect(values.get(TOKEN_STORAGE_KEY)).toBe(status === 401 ? "synthetic-new" : undefined);
  });
}

for (const fail of [false, true]) {
  test(`body ${fail ? "failure" : "success"} after Forget cannot escape the generation guard`, async () => {
    const body = deferred<unknown>();
    const reading = deferred<void>();
    const response = Response.json({});
    response.json = () => { reading.resolve(); return body.promise; };
    globalThis.fetch = async () => response;
    const pending = get("/findings");
    await reading.promise;
    forgetToken();
    if (fail) body.reject(new SyntaxError("old response content"));
    else body.resolve({ secret: "old-data" });
    await expect(pending).rejects.toBeInstanceOf(CredentialsChangedError);
  });
}

test("non-auth error messages retain GET and POST behavior", async () => {
  globalThis.fetch = async () => Response.json({ message: "specific failure" }, { status: 400 });
  await expect(get("/findings")).rejects.toThrow('400 {"message":"specific failure"}');
  await expect(post("/write", {})).rejects.toThrow("400 specific failure");
});

test("invalid header tokens fail without being echoed, saved or sent", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return Response.json({}); };
  await expect(authenticate("synthetic\r\ninjection")).rejects.toThrow("cannot be used as an HTTP header");
  expect(called).toBe(false);
  expect(values.size).toBe(0);
});
