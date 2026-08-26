use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use chrono::{TimeZone, Utc};
use rieko_api::RiekoApi;
use rieko_domain::BitcoinNetwork;
use rieko_findings::{
    ChannelSnapshotReference, Evidence, Finding, FindingLifecycle, FindingProvenance,
    ObservationReference, ObservationSource, ProducerRole, ProducerVersion, Severity,
    FINDING_SCHEMA_VERSION,
};
use rieko_storage::{MemoryStorage, Storage};
use tower::ServiceExt;

fn finding() -> Finding {
    let observed_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    Finding {
        id: "finding/detail".into(),
        detector: "settlement_reliability".into(),
        detector_version: "1".into(),
        schema_version: FINDING_SCHEMA_VERSION,
        severity: Severity::Warning,
        node: Some("node-test".into()),
        channel: None,
        evidence: vec![Evidence {
            key: "invoice_ids".into(),
            value: serde_json::json!(["invoice-a", "invoice-b"]),
        }],
        provenance: Some(FindingProvenance {
            network: Some(BitcoinNetwork::Regtest),
            source: ObservationSource::BtcPay {
                redacted_endpoint: "sha256:endpoint".into(),
                configured_store: "store-test".into(),
                underlying_node: Some("node-test".into()),
            },
            producers: vec![ProducerVersion {
                name: "settlement_reliability".into(),
                version: "1".into(),
                role: ProducerRole::Detector,
            }],
            observation: ObservationReference::ChannelState {
                channel_id: String::new(),
                snapshot: ChannelSnapshotReference {
                    network: Some(BitcoinNetwork::Regtest),
                    observed_at,
                    state_digest: "digest-test".into(),
                },
            },
        }),
        explanation: Some("Persisted explanation".into()),
        timestamp: observed_at,
        first_seen_at: observed_at,
        last_seen_at: observed_at,
        lifecycle: FindingLifecycle::Active,
    }
}

async fn get(app: axum::Router, uri: &str, token: Option<&str>) -> axum::response::Response {
    let mut request = Request::builder().uri(uri);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    app.oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn detail_returns_the_exact_persisted_typed_finding() {
    let expected = finding();
    let mut storage = MemoryStorage::new();
    storage.save_finding(&expected).unwrap();
    let app = RiekoApi::new(Box::new(storage)).unwrap().router();

    let response = get(app, "/findings/finding%2Fdetail", None).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let actual: Finding = serde_json::from_slice(&body).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        actual.evidence[0].value,
        serde_json::json!(["invoice-a", "invoice-b"])
    );
}

#[tokio::test]
async fn detail_returns_not_found_for_an_unknown_id() {
    let app = RiekoApi::new(Box::new(MemoryStorage::new()))
        .unwrap()
        .router();

    let response = get(app, "/findings/missing", None).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    assert_eq!(
        String::from_utf8(body.to_vec()).unwrap(),
        "finding missing not found"
    );
}

#[tokio::test]
async fn detail_requires_the_configured_bearer_token() {
    let app = RiekoApi::new(Box::new(MemoryStorage::new()))
        .unwrap()
        .with_auth("test-token")
        .unwrap()
        .router();

    let unauthorized = get(app.clone(), "/findings/missing", None).await;
    let authorized = get(app, "/findings/missing", Some("test-token")).await;

    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(authorized.status(), StatusCode::NOT_FOUND);
}
