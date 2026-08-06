//! Single-binary UI verification (WP5.1 / RIEKO-AUDIT-009).
//!
//! This test only compiles when `frontend/dist` was present at build time and
//! its assets were embedded into the binary (`rieko_ui_embedded`, set by
//! `build.rs`). It asserts that the read-only API router serves the UI from the
//! binary: `/`, the hashed `/assets/*` files referenced by `index.html`, and the
//! SPA fallback — with no filesystem directory and no Node.js involved.
#![cfg(rieko_ui_embedded)]

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use rieko_api::RiekoApi;
use rieko_storage::MemoryStorage;
use tower::ServiceExt;

async fn get(app: &axum::Router, uri: &str) -> axum::response::Response {
    app.clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn body_text(resp: axum::response::Response) -> String {
    let buf = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn embedded_ui_serves_index_from_binary() {
    let api = RiekoApi::new(Box::new(MemoryStorage::new())).unwrap();
    let app = api.router();

    let resp = get(&app, "/").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(
        html.contains("<title>Rieko</title>"),
        "expected the Rieko UI title, got: {html}"
    );
}

#[tokio::test]
async fn embedded_ui_serves_hashed_assets_referenced_by_index() {
    let api = RiekoApi::new(Box::new(MemoryStorage::new())).unwrap();
    let app = api.router();

    let html = body_text(get(&app, "/").await).await;
    let (js, css) = (first_asset(&html, ".js"), first_asset(&html, ".css"));
    assert!(js.is_some(), "index.html must reference a JS bundle");
    assert!(css.is_some(), "index.html must reference a CSS bundle");

    let js_resp = get(&app, &js.unwrap()).await;
    assert_eq!(js_resp.status(), StatusCode::OK);
    let js_body = body_text(js_resp).await;
    assert!(!js_body.is_empty(), "JS bundle must not be empty");

    let css_resp = get(&app, &css.unwrap()).await;
    assert_eq!(css_resp.status(), StatusCode::OK);
    assert!(
        !body_text(css_resp).await.is_empty(),
        "CSS bundle must not be empty"
    );
}

#[tokio::test]
async fn embedded_ui_returns_404_for_unknown_paths() {
    // The v1 UI is a single page with no client-side routing; unknown paths
    // return 404 from the API router — there is no SPA fallback.
    let api = RiekoApi::new(Box::new(MemoryStorage::new())).unwrap();
    let app = api.router();

    let resp = get(&app, "/some/client/route").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unknown_asset_is_404() {
    let api = RiekoApi::new(Box::new(MemoryStorage::new())).unwrap();
    let app = api.router();
    let resp = get(&app, "/assets/does-not-exist.js").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

fn first_asset(html: &str, ext: &str) -> Option<String> {
    let needle = "/assets/index-";
    let mut search_from = 0;
    while let Some(start) = html[search_from..].find(needle) {
        let start = search_from + start;
        let rest = &html[start..];
        if let Some(ext_pos) = rest.find(ext) {
            let candidate = &rest[..ext_pos + ext.len()];
            if !candidate.contains(['"', '\'']) {
                return Some(candidate.to_string());
            }
        }
        search_from = start + needle.len();
    }
    None
}
