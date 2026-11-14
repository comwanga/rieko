<script lang="ts">
  // Neutral, hand-drawn glyphs. No third-party icon set or brand mark is used.
  export let name: keyof typeof PATHS;

  const PATHS = {
    logo: "M12 3 4 7v6c0 4 3.4 7 8 8 4.6-1 8-4 8-8V7Zm0 5v8",
    home: "M4 11 12 4l8 7M6 10v9h4v-5h4v5h4v-9",
    alert: "M12 4 3 19h18ZM12 10v4M12 16.5v.5",
    check: "M5 12.5 10 17l9-10",
    play: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM10 8.5v7l6-3.5Z",
    layers: "M12 4 3 9l9 5 9-5ZM3 14l9 5 9-5",
    list: "M8 6h12M8 12h12M8 18h12M4 6h.5M4 12h.5M4 18h.5",
    sun: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M5 19l1.5-1.5M17.5 6.5 19 5",
    moon: "M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5Z",
    menu: "M4 7h16M4 12h16M4 17h16",
    external: "M14 5h5v5M19 5l-8 8M11 7H6v11h11v-5",
    blocks: "M4 4h7v7H4ZM13 4h7v7h-7ZM4 13h7v7H4ZM13 13h7v7h-7Z",
    bolt: "M13 3 5 13h6l-1 8 8-10h-6Z",
    store: "M4 9h16l-1.5-4h-13ZM5 9v10h14V9M9 19v-5h6v5",
    database: "M12 4c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3ZM4 7v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  };
</script>

<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7"
  stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
  <path d={PATHS[name]} />
</svg>

<style>
  svg { flex: none; }
</style>
