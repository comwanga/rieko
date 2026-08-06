//! Embedded frontend assets (WP5.1 / RIEKO-AUDIT-009).
//!
//! When `frontend/dist` exists at compile time, `build.rs` embeds every asset
//! via `include_bytes!` into the binary and sets the `rieko_ui_embedded` cfg.
//! The `serve` command then delivers the UI from the binary itself — no Node.js
//! at runtime, no external `dist` directory, no specific working directory.
//!
//! In a debug build created without `frontend/dist`, `embedded::available()`
//! is false and the app falls back to the optional filesystem `--static-dir`
//! (dev mode).

#[cfg(rieko_ui_embedded)]
pub(crate) mod embedded {
    include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));

    /// The content type for a served asset, derived from its extension.
    fn mime_of(path: &str) -> &'static str {
        let ext = path.rsplit('.').next().unwrap_or("");
        match ext {
            "html" => "text/html; charset=utf-8",
            "js" | "mjs" => "text/javascript; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "svg" => "image/svg+xml",
            "json" | "map" => "application/json",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "ico" => "image/x-icon",
            "woff" => "font/woff",
            "woff2" => "font/woff2",
            "txt" => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        }
    }

    /// Return the bytes and content type for an exact asset path (e.g.
    /// `assets/index-abc123.js`), or `None` if unknown.
    pub fn get(path: &str) -> Option<(&'static [u8], &'static str)> {
        ASSETS
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(p, bytes)| (*bytes, mime_of(p)))
    }

    pub fn index_html() -> Option<&'static [u8]> {
        ASSETS
            .iter()
            .find(|(p, _)| *p == "index.html")
            .map(|(_, bytes)| *bytes)
    }

    pub fn available() -> bool {
        true
    }

    /// Serve an asset under `/assets/*path`.
    pub async fn asset(
        axum::extract::Path(path): axum::extract::Path<String>,
    ) -> axum::response::Response {
        // axum 0.7 wildcard extraction is inconsistent about a leading slash
        // and whether the `assets/` prefix is included; normalize to the bare
        // relative filename and re-add the stable store prefix `assets/`.
        let key = path.trim_matches('/');
        let key = key.strip_prefix("assets/").unwrap_or(key);
        let key = format!("assets/{key}");
        match get(&key) {
            Some((bytes, mime)) => reply(bytes, mime),
            None => axum::response::Response::builder()
                .status(axum::http::StatusCode::NOT_FOUND)
                .body(axum::body::Body::empty())
                .unwrap(),
        }
    }

    /// Serve the SPA entry point at `/`.
    pub async fn index() -> axum::response::Response {
        match index_html() {
            Some(bytes) => reply(bytes, "text/html; charset=utf-8"),
            None => axum::response::Response::builder()
                .status(axum::http::StatusCode::NOT_FOUND)
                .body(axum::body::Body::empty())
                .unwrap(),
        }
    }

    fn reply(bytes: &'static [u8], mime: &'static str) -> axum::response::Response {
        let mut resp = axum::response::Response::new(axum::body::Body::from(bytes));
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static(mime),
        );
        resp
    }
}

#[cfg(not(rieko_ui_embedded))]
pub(crate) mod embedded {
    /// No UI was embedded at compile time (dev build without `frontend/dist`).
    /// Serving falls back to the optional filesystem `--static-dir`.
    pub fn available() -> bool {
        false
    }
}
