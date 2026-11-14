import { writable } from "svelte/store";

export const ROUTES = [
  { id: "overview", label: "Overview", icon: "home" },
  { id: "findings", label: "Findings", icon: "alert" },
  { id: "recommendations", label: "Recommendations", icon: "check" },
  { id: "simulations", label: "Simulations", icon: "play" },
  { id: "channels", label: "Channels", icon: "layers" },
  { id: "audit", label: "Audit", icon: "list" },
] as const;

export type RouteId = (typeof ROUTES)[number]["id"];

/** Unknown, empty and malformed hashes resolve to the Overview. */
export function parseRoute(hash: string): RouteId {
  const id = hash.replace(/^#\/?/, "").split(/[/?]/)[0];
  return ROUTES.find(route => route.id === id)?.id ?? "overview";
}

export function routeHref(id: RouteId): string {
  return `#/${id}`;
}

const store = writable<RouteId>("overview");
export const route = { subscribe: store.subscribe };

/** Follow the URL hash. `onNavigate` runs for changes after the initial load only. */
export function startRouter(onNavigate: () => void): () => void {
  const sync = () => {
    const id = parseRoute(window.location.hash);
    store.set(id);
    document.title = `${ROUTES.find(candidate => candidate.id === id)!.label} · Rieko`;
  };
  const changed = () => {
    sync();
    onNavigate();
  };
  sync();
  window.addEventListener("hashchange", changed);
  return () => window.removeEventListener("hashchange", changed);
}
