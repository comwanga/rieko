import { writable } from "svelte/store";

export type Theme = "dark" | "light";
export const THEME_STORAGE_KEY = "rieko.theme";

const store = writable<Theme>("dark");
export const theme = { subscribe: store.subscribe };

function apply(value: Theme) {
  document.documentElement.dataset.theme = value;
  store.set(value);
}

/** Dark is the default. A saved choice is honoured; unreadable storage is not an error. */
export function initializeTheme() {
  let saved: string | null = null;
  try {
    saved = window.localStorage.getItem(THEME_STORAGE_KEY);
  } catch { /* The default theme applies for this page. */ }
  apply(saved === "light" ? "light" : "dark");
}

export function setTheme(value: Theme) {
  apply(value);
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, value);
  } catch { /* The choice still applies until this page is closed. */ }
}
