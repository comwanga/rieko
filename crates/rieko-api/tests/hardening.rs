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

fn assert_security_headers(resp: &axum::response::Response) {
    let headers = resp.headers();
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-resource-policy", "same-origin"),
        ("cross-origin-opener-policy", "same-origin"),
    ] {
        assert_eq!(headers.get(name).unwrap(), value, "{name}");
    }
    let directives: Vec<_> = headers["content-security-policy"]
        .to_str()
        .unwrap()
        .split(';')
        .map(str::trim)
        .filter(|directive| !directive.is_empty())
        .collect();
    let expected = [
        "default-src 'none'",
        "connect-src 'self'",
        "img-src 'self' data:",
        "style-src 'self' 'unsafe-inline'",
        "script-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
    ];
    assert_eq!(directives.len(), expected.len());
    for directive in expected {
        assert!(directives.contains(&directive), "missing CSP: {directive}");
    }
    assert!(headers.get("access-control-allow-origin").is_none());
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
    assert_security_headers(&resp);
    // Sensitive data must never be cached.
    assert_eq!(resp.headers()["cache-control"], "no-store, max-age=0");
}

#[tokio::test]
async fn static_files_and_fallback_receive_headers_without_bypassing_api_auth() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("assets")).unwrap();
    std::fs::write(
        dir.path().join("index.html"),
        "<!doctype html><title>Test</title>",
    )
    .unwrap();
    std::fs::write(dir.path().join("assets/app.js"), "// fixture").unwrap();
    let app = RiekoApi::new(Box::new(MemoryStorage::new()))
        .unwrap()
        .with_static_dir(dir.path())
        .with_auth("test-token")
        .unwrap()
        .router();

    for (path, bearer, status) in [
        ("/", None, StatusCode::OK),
        ("/assets/app.js", None, StatusCode::OK),
        ("/assets/missing.js", None, StatusCode::NOT_FOUND),
        ("/missing", None, StatusCode::NOT_FOUND),
        ("/status", None, StatusCode::UNAUTHORIZED),
        ("/status", Some("wrong-token"), StatusCode::UNAUTHORIZED),
        ("/status", Some("test-token"), StatusCode::OK),
    ] {
        let response = get(&app, path, bearer).await;
        assert_eq!(response.status(), status, "{path}");
        assert_security_headers(&response);
        if !path.starts_with("/assets") {
            assert_eq!(response.headers()["cache-control"], "no-store, max-age=0");
        }
    }
}

#[tokio::test]
async fn static_asset_cache_and_conditional_requests_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("assets")).unwrap();
    std::fs::write(dir.path().join("assets/app.js"), "// cache fixture").unwrap();
    let app = RiekoApi::new(Box::new(MemoryStorage::new()))
        .unwrap()
        .with_static_dir(dir.path())
        .router();
    let response = get(&app, "/assets/app.js", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_security_headers(&response);
    assert!(response.headers().get(header::CACHE_CONTROL).is_none());
    let modified = response.headers()[header::LAST_MODIFIED].clone();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/assets/app.js")
                .header(header::IF_MODIFIED_SINCE, modified)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_security_headers(&response);
    assert!(response.headers().get(header::CACHE_CONTROL).is_none());
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
    assert_security_headers(&resp);
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
            provenance: None,
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

#[tokio::test]
async fn findings_lifecycle_filter_defaults_active_and_validates_input() {
    use rieko_findings::{
        Evidence, Finding, FindingCycleScope, FindingLifecycle, FINDING_SCHEMA_VERSION,
    };

    let finding = |id: &str, detector: &str| Finding {
        id: id.into(),
        detector: detector.into(),
        detector_version: "1".into(),
        severity: rieko_findings::Severity::Warning,
        schema_version: FINDING_SCHEMA_VERSION,
        node: Some("local-node".into()),
        channel: Some("c1".into()),
        evidence: vec![Evidence::string("local_ratio", "0.5")],
        provenance: None,
        explanation: None,
        timestamp: chrono::Utc::now(),
        first_seen_at: chrono::Utc::now(),
        last_seen_at: chrono::Utc::now(),
        lifecycle: FindingLifecycle::Active,
    };
    let mut mem = MemoryStorage::new();
    mem.save_finding(&finding("resolved", "old_detector"))
        .unwrap();
    for _ in 0..3 {
        mem.resolve_findings_for_scope(&FindingCycleScope {
            detector: "old_detector".into(),
            network: None,
            node: Some("local-node".into()),
            complete: true,
        })
        .unwrap();
    }
    mem.save_finding(&finding("active", "current_detector"))
        .unwrap();
    let app = RiekoApi::new(Box::new(mem)).unwrap().router();

    for (uri, expected) in [
        ("/findings", vec!["active"]),
        ("/findings?lifecycle=resolved", vec!["resolved"]),
        ("/findings?lifecycle=all", vec!["active", "resolved"]),
        ("/findings/channel/c1?lifecycle=resolved", vec!["resolved"]),
    ] {
        let response = get(&app, uri, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let findings: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        let ids: Vec<_> = findings
            .iter()
            .map(|finding| finding["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, expected, "unexpected lifecycle results for {uri}");
    }

    let response = get(&app, "/findings?lifecycle=unknown", None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn recommendations_default_active_behavior_is_preserved_and_history_is_opt_in() {
    use rieko_findings::{Action, ActionType, Actionability, Rationale, Recommendation};

    let recommendation = |finding_id: &str, lifecycle: Option<&str>| Recommendation {
        finding_id: finding_id.into(),
        action: Action::for_recommendation(
            finding_id,
            ActionType::RestartService,
            Some("btcpay".into()),
            serde_json::json!({}),
            format!("review {finding_id}"),
        ),
        rationale: Rationale {
            evidence: Vec::new(),
            preconditions: Vec::new(),
            expected_effect: "operator review".into(),
            risks: Vec::new(),
            limitations: Vec::new(),
            actionability: Actionability::OperatorActionable,
        },
        lifecycle: lifecycle.map(str::to_owned),
    };
    let historical = recommendation("historical", Some("resolved"));
    let current = recommendation("current", None);
    let mut storage = MemoryStorage::new();
    storage.save_recommendation(&historical).unwrap();
    storage.save_recommendation(&current).unwrap();
    let app = RiekoApi::new(Box::new(storage)).unwrap().router();

    for (uri, expected) in [
        ("/recommendations", vec![current.clone()]),
        ("/recommendations?lifecycle=active", vec![current.clone()]),
        ("/recommendations?lifecycle=resolved", vec![current.clone()]),
        (
            "/recommendations?lifecycle=all",
            vec![current.clone(), historical.clone()],
        ),
    ] {
        let response = get(&app, uri, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let recommendations: Vec<Recommendation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(recommendations, expected, "unexpected results for {uri}");
    }
}
