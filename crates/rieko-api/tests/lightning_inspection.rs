use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use chrono::{TimeZone, Utc};
use rieko_api::routes::LightningInspection;
use rieko_api::RiekoApi;
use rieko_domain::LightningSnapshot;
use rieko_status::{LightningState, OperationalState, OperationalStateStore};
use rieko_storage::MemoryStorage;
use tower::ServiceExt;

#[tokio::test]
async fn returns_exact_persisted_lightning_state() {
    let observed_at = Utc.with_ymd_and_hms(2026, 8, 27, 10, 0, 0).unwrap();
    let expected = LightningState {
        connected: true,
        last_attempt: observed_at,
        last_success: Some(observed_at),
        snapshot: Some(LightningSnapshot {
            node_id: "02abc".into(),
            synced_to_chain: false,
            active_channels: 3,
            inactive_channels: 1,
            observed_at,
        }),
    };
    let mut storage = MemoryStorage::new();
    storage
        .write_operational_state(&OperationalState {
            lightning: Some(expected.clone()),
            ..Default::default()
        })
        .unwrap();

    let response = RiekoApi::new(Box::new(storage))
        .unwrap()
        .router()
        .oneshot(
            Request::builder()
                .uri("/inspect/lightning")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let inspection: LightningInspection = serde_json::from_slice(&body).unwrap();
    assert_eq!(inspection.state, Some(expected));
}

#[tokio::test]
async fn requires_configured_authentication() {
    let app = RiekoApi::new(Box::new(MemoryStorage::new()))
        .unwrap()
        .with_auth("top-secret")
        .unwrap()
        .router();

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/inspect/lightning")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = app
        .oneshot(
            Request::builder()
                .uri("/inspect/lightning")
                .header(header::AUTHORIZATION, "Bearer top-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);
}
