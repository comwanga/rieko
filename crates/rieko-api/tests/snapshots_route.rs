use axum::body::to_bytes;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use rieko_api::RiekoApi;
use rieko_domain::{ChannelSnapshot, ChannelStatus};
use rieko_findings::{
    Action, ActionStage, ActionType, Evidence, Finding, FindingLifecycle, Rationale,
    Recommendation, Severity, FINDING_SCHEMA_VERSION,
};
use rieko_status::OperationalStateStore;
use rieko_storage::{MemoryStorage, Storage};
use tower::ServiceExt;

#[tokio::test]
async fn snapshots_path_param_route_reachable() {
    let mut mem = MemoryStorage::new();
    let snap = ChannelSnapshot {
        node_id: Some("local-node".into()),
        channel_id: "abc123x0".to_string(),
        local_ratio: 0.42,
        local_balance_msat: 420_000,
        remote_balance_msat: 580_000,
        capacity_msat: 1_000_000,
        status: ChannelStatus::Active,
        ts: Utc::now(),
        spendable_outbound_msat: 0,
        spendable_inbound_msat: 0,
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
        .clone()
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

#[cfg(feature = "simulate")]
#[tokio::test]
async fn simulations_route_returns_persisted_sims() {
    use rieko_findings::{ActionType, Simulation, SimulationProjection};
    use rieko_storage::SimulationRecord;

    let mut mem = MemoryStorage::new();
    let now = Utc::now().to_rfc3339();
    let sim = SimulationRecord {
        id: "sim1".into(),
        action_id: "action1".into(),
        finding_id: "f1".into(),
        action_type: "rebalance_channel".into(),
        status: "completed".into(),
        model_id: "legacy".into(),
        model_version: "0".into(),
        input_hash: String::new(),
        confidence: "unknown".into(),
        assumptions: serde_json::json!([]),
        warnings: serde_json::json!([]),
        explanation: String::new(),
        canonical_input: serde_json::Value::Null,
        projection: serde_json::json!({"clears_finding": true}),
        source_observed_at: Some("2020-01-01T00:00:00Z".into()),
        requested_at: now.clone(),
        completed_at: Some(now.clone()),
        error_code: None,
        created_at: now,
    };
    mem.save_simulation_v2(&sim).unwrap();
    mem.save_simulation(&Simulation {
        id: "legacy-sim".into(),
        action_id: "legacy-action".into(),
        finding_id: "legacy-finding".into(),
        action_type: ActionType::RebalanceChannel,
        projection: SimulationProjection {
            local_ratio_before: 0.2,
            local_ratio_after: 0.3,
            local_balance_msat_after: 300,
            remote_balance_msat_after: 700,
            delta_msat: 100,
            clears_finding: false,
            summary: "legacy projection".into(),
        },
        created_at: Utc::now(),
    })
    .unwrap();

    let app = RiekoApi::new(Box::new(mem)).unwrap().router();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/simulations/v2")
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
    assert_eq!(arr[0]["status"], "stale");

    let detail = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/simulations/sim1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);

    let legacy = app
        .oneshot(
            Request::builder()
                .uri("/simulations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(legacy.into_body(), 4096).await.unwrap();
    let records: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(records[0]["id"], "legacy-sim");
}

#[cfg(not(feature = "simulate"))]
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
        provenance: None,
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
        rationale: Rationale::default(),
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
        rationale: Rationale::default(),
    })
    .unwrap();

    mem.save_channel_snapshot(&ChannelSnapshot {
        node_id: Some("local-node".into()),
        channel_id: "abc123x0".into(),
        local_ratio: 0.5,
        local_balance_msat: 500_000,
        remote_balance_msat: 500_000,
        capacity_msat: 1_000_000,
        status: ChannelStatus::Active,
        ts: Utc::now(),
        spendable_outbound_msat: 0,
        spendable_inbound_msat: 0,
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
    assert_eq!(json["read_only"], cfg!(not(feature = "execute")));
    assert_eq!(json["overall"], "not_initialized");
}

#[tokio::test]
async fn status_exposes_source_data_timestamp() {
    let source_data_at = chrono::DateTime::parse_from_rfc3339("2026-08-10T12:34:56Z")
        .unwrap()
        .with_timezone(&Utc);
    let mut mem = MemoryStorage::new();
    mem.write_operational_state(&rieko_status::OperationalState {
        last_ingestion_success: Some(source_data_at),
        source_data_at: Some(source_data_at),
        ..Default::default()
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
    assert_eq!(json["source_data_at"], source_data_at.to_rfc3339());
}
