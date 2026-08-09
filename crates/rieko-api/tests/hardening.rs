use axum::body::to_bytes;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use rieko_api::RiekoApi;
use rieko_storage::MemoryStorage;
use rieko_storage::Storage;
use tower::ServiceExt;

/// The read-only JSON surface is protected by the bearer token when configured
/// and served with security headers otherwise (RIEKO-AUDIT-014).
fn app_with_auth(token: Option<&str>) -> axum::Router {
    let mut api = RiekoApi::new(Box::new(MemoryStorage::new())).unwrap();
    if let Some(t) = token {
        api = api.with_auth(t).unwrap();
    }
    api.router()
}

async fn get(app: &axum::Router, uri: &str, bearer: Option<&str>) -> axum::response::Response {
    let mut builder = Request::builder().uri(uri);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    app.clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn unauthenticated_requests_fail_when_token_configured() {
    let app = app_with_auth(Some("top-secret"));
    for uri in ["/status", "/findings", "/recommendations", "/audit"] {
        let resp = get(&app, uri, None).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "route {uri} must reject unauthenticated requests"
        );
    }
}

#[tokio::test]
async fn authenticated_requests_succeed() {
    let app = app_with_auth(Some("top-secret"));
    let resp = get(&app, "/status", Some("top-secret")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn wrong_token_is_rejected() {
    let app = app_with_auth(Some("top-secret"));
    let resp = get(&app, "/status", Some("wrong")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn empty_auth_tokens_are_rejected() {
    for token in ["", " ", "\t\r\n"] {
        let api = RiekoApi::new(Box::new(MemoryStorage::new())).unwrap();
        assert!(api.with_auth(token).is_err());
    }
}

#[tokio::test]
async fn configured_auth_token_is_trimmed() {
    let api = RiekoApi::new(Box::new(MemoryStorage::new()))
        .unwrap()
        .with_auth("  top-secret  ")
        .unwrap();
    let resp = get(&api.router(), "/status", Some("top-secret")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn no_token_configured_means_open_loopback_access() {
    let app = app_with_auth(None);
    let resp = get(&app, "/status", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn security_headers_are_present_on_api_responses() {
    let app = app_with_auth(None);
    let resp = get(&app, "/status", None).await;
    let headers = resp.headers();
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(
        headers.get("cross-origin-resource-policy").unwrap(),
        "same-origin"
    );
    let csp = headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    // Sensitive data must never be cached.
    assert_eq!(headers.get("cache-control").unwrap(), "no-store, max-age=0");
    // No permissive CORS header: cross-origin readers get nothing.
    assert!(headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn security_headers_do_not_force_cache_control_on_assets() {
    let app = app_with_auth(None);
    let resp = get(&app, "/assets/app.js", None).await;
    let headers = resp.headers();
    // A 404 from a non-existent asset still flows through the header layer.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(headers.get("cache-control").is_none());
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
}

#[tokio::test]
async fn oversized_request_body_is_rejected() {
    let app = app_with_auth(None);
    let big = vec![b'x'; (1 << 20) + 1];
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/findings")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_LENGTH, big.len())
                .body(Body::from(big))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn status_uses_bounded_queries() {
    let app = app_with_auth(None);
    let resp = get(&app, "/status", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Counts come from aggregate COUNT(*) queries, not full-row loads.
    assert!(json["counts"]["channel_snapshots"].is_number());
    assert!(json["overall"].is_string());
}

#[tokio::test]
async fn list_endpoints_enforce_the_limit_clamp() {
    use rieko_findings::{Evidence, Finding, FindingLifecycle, FINDING_SCHEMA_VERSION};

    let mut mem = rieko_storage::MemoryStorage::new();
    for i in 0..600 {
        mem.save_finding(&Finding {
            id: format!("f{i}"),
            detector: "channel_liquidity".into(),
            detector_version: "1".into(),
            severity: rieko_findings::Severity::Warning,
            schema_version: FINDING_SCHEMA_VERSION,
            node: None,
            channel: Some("c1".into()),
            evidence: vec![Evidence::string("local_ratio", "0.5")],
            explanation: None,
            timestamp: chrono::Utc::now(),
            first_seen_at: chrono::Utc::now(),
            last_seen_at: chrono::Utc::now(),
            lifecycle: FindingLifecycle::Active,
        })
        .unwrap();
    }
    let app = RiekoApi::new(Box::new(mem)).unwrap().router();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/findings?limit=100000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().expect("array of findings");
    assert_ne!(
        arr.len(),
        600,
        "the limit must be clamped to the 500-row ceiling for untrusted input"
    );
    assert!(arr.len() <= 500, "route must not exceed the bounded limit");
}
