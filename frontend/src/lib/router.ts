import { writable } from "svelte/store";

export const ROUTES = [
  { id: "overview", label: "Overview", icon: "home" },
  { id: "findings", label: "Findings", icon: "alert" },
  { id: "recommendations", label: "Recommendations", icon: "check" },
  { id: "simulations", label: "Simulations", icon: "play" },
  { id: "services", label: "Services", icon: "layers" },
  { id: "audit", label: "Audit", icon: "list" },
] as const;

export type RouteId = (typeof ROUTES)[number]["id"];

export interface Location {
  id: RouteId;
  /** A finding identifier, only for `#/findings/<id>`. */
  param: string | null;
}

/** Unknown views resolve to Overview; malformed finding identifiers are ignored. */
export function parseLocation(hash: string): Location {
  const [head, next] = hash.replace(/^#\/?/, "").split("?")[0].split("/");
  const id = ROUTES.find(route => route.id === head)?.id ?? (head === "channels" ? "services" : "overview");
  let param: string | null = null;
  if (id === "findings" && head === "findings" && next) {
    try {
      param = decodeURIComponent(next);
    } catch {
      param = null;
    }
  }
  return { id, param };
}

export function parseRoute(hash: string): RouteId {
  return parseLocation(hash).id;
}

export function routeHref(id: RouteId): string {
  return `#/${id}`;
}

export function findingHref(findingId: string): string {
  return `#/findings/${encodeURIComponent(findingId)}`;
}

const store = writable<RouteId>("overview");
export const route = { subscribe: store.subscribe };
const paramStore = writable<string | null>(null);
export const routeParam = { subscribe: paramStore.subscribe };

/** Follow the URL hash. `onNavigate` runs for changes after the initial load only. */
export function startRouter(onNavigate: () => void): () => void {
  const sync = () => {
    const location = parseLocation(window.location.hash);
    store.set(location.id);
    paramStore.set(location.param);
    const label = location.param ? "Finding" : ROUTES.find(candidate => candidate.id === location.id)!.label;
    document.title = `${label} · Rieko`;
  };
  const changed = () => {
    sync();
    onNavigate();
  };
  sync();
  window.addEventListener("hashchange", changed);
  return () => window.removeEventListener("hashchange", changed);
}
