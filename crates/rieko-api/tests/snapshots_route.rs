use axum::body::to_bytes;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use rieko_api::RiekoApi;
use rieko_domain::{ChannelSnapshot, ChannelStatus};
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
