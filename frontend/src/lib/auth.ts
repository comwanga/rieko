import { writable } from "svelte/store";

export const TOKEN_STORAGE_KEY = "rieko.apiToken";
type StorageMode = "session" | "memory" | "clear-failed";
interface AuthState {
  generation: number;
  required: boolean;
  hasToken: boolean;
  storage: StorageMode;
}

let token: string | undefined;
let generation = 0;
let storage: StorageMode = "session";
const state = writable<AuthState>({ generation, required: false, hasToken: false, storage });
export const authState = { subscribe: state.subscribe };

export class AuthenticationError extends Error {
  constructor(message = "An API token is required.") {
    super(message);
    this.name = "AuthenticationError";
  }
}

export class CredentialsChangedError extends AuthenticationError {
  constructor() {
    super("Credentials changed. Requests are not replayed; retry manually if needed.");
    this.name = "CredentialsChangedError";
  }
}

function publish(required: boolean) {
  state.set({ generation, required, hasToken: Boolean(token), storage });
}

export function initializeAuth() {
  generation++;
  token = undefined;
  storage = "session";
  try {
    token = window.sessionStorage.getItem(TOKEN_STORAGE_KEY)?.trim() || undefined;
  } catch {
    storage = "memory";
  }
  publish(false);
}

export function credentialSnapshot() {
  return { token, generation };
}

export function assertCurrent(expected: number) {
  if (generation !== expected) throw new CredentialsChangedError();
}

export function saveValidatedToken(value: string, expected: number) {
  assertCurrent(expected);
  try {
    window.sessionStorage.setItem(TOKEN_STORAGE_KEY, value);
    storage = "session";
  } catch {
    if (storage !== "clear-failed") storage = "memory";
  }
  token = value;
  generation++;
  publish(false);
}

function clearCredential(required: boolean) {
  token = undefined;
  generation++;
  try {
    window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    if (storage === "clear-failed") storage = "session";
  } catch {
    storage = "clear-failed";
  }
  publish(required);
}

export function forgetToken() {
  clearCredential(false);
}

export function rejectCredential(expected: number) {
  assertCurrent(expected);
  clearCredential(true);
}
