import { mount } from "svelte";
import App from "./App.svelte";
import { setupApiBase } from "./lib/api";
import "./app.css";

// The API and the UI are served from the same origin by the Rust binary, so a
// relative base works; the injection hook exists for dev setups behind a proxy.
setupApiBase((window as any).__RIEKO_API_BASE__ ?? "");

mount(App, {
  target: document.getElementById("app")!,
});