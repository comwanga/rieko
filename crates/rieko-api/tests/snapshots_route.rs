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
    assert_eq!(status, StatusCode::OK, "status={status} body: {}", String::from_utf8_lossy(&body));
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().expect("expected array of snapshots");
    assert_eq!(arr.len(), 1, "expected one snapshot back");
    assert_eq!(arr[0]["channel_id"], "abc123x0");
    assert_eq!(arr[0]["local_ratio"], 0.42);
}
