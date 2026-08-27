use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use chrono::{TimeZone, Utc};
use rieko_api::routes::{BtcPayInspection, BtcPayInspectionState};
use rieko_api::RiekoApi;
use rieko_status::{OperationalState, OperationalStateStore, SourceState};
use rieko_storage::MemoryStorage;
use tower::ServiceExt;

#[tokio::test]
async fn returns_exact_persisted_btcpay_state() {
    let observed_at = Utc.with_ymd_and_hms(2026, 8, 27, 10, 0, 0).unwrap();
    let expected = BtcPayInspectionState {
        source: SourceState::BtcPayGreenfield { connected: false },
        last_attempt: Some(observed_at),
        last_success: Some(observed_at),
        source_data_at: Some(observed_at),
    };
    let mut storage = MemoryStorage::new();
    storage
        .write_operational_state(&OperationalState {
            source: expected.source,
            last_ingestion_attempt: expected.last_attempt,
            last_ingestion_success: expected.last_success,
            source_data_at: expected.source_data_at,
            ..Default::default()
        })
        .unwrap();

    let response = RiekoApi::new(Box::new(storage))
        .unwrap()
        .router()
        .oneshot(
            Request::builder()
                .uri("/inspect/btcpay")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let inspection: BtcPayInspection = serde_json::from_slice(&body).unwrap();
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
                .uri("/inspect/btcpay")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = app
        .oneshot(
            Request::builder()
                .uri("/inspect/btcpay")
                .header(header::AUTHORIZATION, "Bearer top-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);
}
