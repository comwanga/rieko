<reference types="svelte" />
<reference types="vite/client" />

declare global {
  interface Window {
    /** Injected by the Rust API server; e.g. http://127.0.0.1:8080 */
    __RIEKO_API_BASE__?: string;
  }
}

export {}
