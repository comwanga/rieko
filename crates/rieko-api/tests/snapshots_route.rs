use axum::body::to_bytes;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use rieko_api::RiekoApi;
use rieko_domain::{ChannelSnapshot, ChannelStatus};
use rieko_findings::{
    Action, ActionStage, ActionType, Evidence, Finding, FindingLifecycle, Recommendation, Severity,
    FINDING_SCHEMA_VERSION,
};
use rieko_storage::{MemoryStorage, Storage};
use tower::ServiceExt;

#[tokio::test]
async fn snapshots_path_param_route_reachable() {
    let mut mem = MemoryStorage::new();
    let snap = ChannelSnapshot {
        channel_id: "abc123x0".to_string(),
        local_ratio: 0.42,
        local_balance_msat: 420_000,
        remote_balance_msat: 580_000,
        capacity_msat: 1_000_000,
        status: ChannelStatus::Active,
        ts: Utc::now(),
    };
    mem.save_channel_snapshot(&snap).unwrap();
    let api = RiekoApi::new(Box::new(mem)).unwrap();
    let app = api.router();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "status route should work");

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/snapshots/channel/abc123x0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "status={status} body: {}",
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().expect("expected array of snapshots");
    assert_eq!(arr.len(), 1, "expected one snapshot back");
    assert_eq!(arr[0]["channel_id"], "abc123x0");
    assert_eq!(arr[0]["local_ratio"], 0.42);
}

#[cfg(feature = "future")]
#[tokio::test]
async fn simulations_route_returns_persisted_sims() {
    use rieko_findings::{Action, ActionStage, ActionType, Simulation, SimulationProjection};

    let mut mem = MemoryStorage::new();
    let action = Action::new(
        ActionType::RebalanceChannel,
        ActionStage::Recommended,
        Some("c1".into()),
        serde_json::json!({ "desired_ratio": 0.5 }),
        "rebalance",
    );
    let sim = Simulation {
        id: "sim1".into(),
        action_id: action.id.clone(),
        finding_id: "f1".into(),
        action_type: ActionType::RebalanceChannel,
        projection: SimulationProjection {
            local_ratio_before: 0.1,
            local_ratio_after: 0.5,
            local_balance_msat_after: 50_000,
            remote_balance_msat_after: 50_000,
            delta_msat: 40_000,
            clears_finding: true,
            summary: "would clear the finding".into(),
        },
        created_at: Utc::now(),
    };
    mem.save_simulation(&sim).unwrap();

    let app = RiekoApi::new(Box::new(mem)).unwrap().router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/simulations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().expect("expected array of simulations");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["action_id"], sim.action_id);
    assert!(arr[0]["projection"]["clears_finding"].as_bool().unwrap());
}

#[cfg(not(feature = "future"))]
#[tokio::test]
async fn simulations_route_is_absent_in_read_only_v1() {
    let mem = MemoryStorage::new();
    let app = RiekoApi::new(Box::new(mem)).unwrap().router();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/simulations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "the read-only v1 API must not expose /simulations"
    );

    for (method, uri) in [
        ("POST", "/simulations"),
        ("PUT", "/simulations"),
        ("DELETE", "/simulations"),
        ("POST", "/findings"),
        ("POST", "/audit"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::NOT_FOUND
                || resp.status() == StatusCode::METHOD_NOT_ALLOWED,
            "no mutation endpoint expected for {method} {uri}, got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn status_reports_operational_counts() {
    let mut mem = MemoryStorage::new();

    let warning = Finding {
        id: "f-warn".into(),
        detector: "channel_liquidity".into(),
        detector_version: "1".into(),
        severity: Severity::Warning,
        schema_version: FINDING_SCHEMA_VERSION,
        node: None,
        channel: Some("abc123x0".into()),
        evidence: vec![Evidence::string("local_ratio", "0.9")],
        explanation: None,
        timestamp: Utc::now(),
        first_seen_at: Utc::now(),
        last_seen_at: Utc::now(),
        lifecycle: FindingLifecycle::Active,
    };
    mem.save_finding(&warning).unwrap();
    mem.save_finding(&Finding {
        id: "f-crit".into(),
        severity: Severity::Critical,
        evidence: Vec::new(),
        ..warning
    })
    .unwrap();

    let action = Action::new(
        ActionType::RebalanceChannel,
        ActionStage::Recommended,
        Some("abc123x0".into()),
        serde_json::json!({ "desired_ratio": 0.5 }),
        "rebalance",
    );
    mem.save_recommendation(&Recommendation {
        finding_id: "f-warn".into(),
        action: action.clone(),
    })
    .unwrap();
    mem.save_recommendation(&Recommendation {
        finding_id: "f-warn".into(),
        action: Action::new(
            ActionType::RebalanceChannel,
            ActionStage::Executed,
            None,
            serde_json::json!({}),
            "noop",
        ),
    })
    .unwrap();

    mem.save_channel_snapshot(&ChannelSnapshot {
        channel_id: "abc123x0".into(),
        local_ratio: 0.5,
        local_balance_msat: 500_000,
        remote_balance_msat: 500_000,
        capacity_msat: 1_000_000,
        status: ChannelStatus::Active,
        ts: Utc::now(),
    })
    .unwrap();

    let app = RiekoApi::new(Box::new(mem)).unwrap().router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["counts"]["findings"], 2);
    assert_eq!(json["counts"]["recommendations"], 2);
    assert_eq!(json["counts"]["simulations"], 0);
    assert_eq!(json["counts"]["channel_snapshots"], 1);
    assert_eq!(json["counts"]["audit"], 0);
    assert_eq!(json["engine"], "rieko");
    assert_eq!(json["read_only"], cfg!(not(feature = "future")));
    assert_eq!(json["overall"], "not_initialized");
}
