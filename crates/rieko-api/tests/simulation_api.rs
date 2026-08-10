#![cfg(feature = "simulate")]

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use chrono::Utc;
use rieko_api::RiekoApi;
use rieko_domain::{ChannelSnapshot, ChannelStatus};
use rieko_findings::{
    Action, ActionType, Actionability, ChannelSnapshotReference, Finding, FindingLifecycle,
    FindingProvenance, ObservationReference, ObservationSource, Rationale, Recommendation,
    Severity, FINDING_SCHEMA_VERSION,
};
use rieko_storage::{MemoryStorage, Storage};
use tower::ServiceExt;

fn snapshot(
    channel_id: &str,
    local: u64,
    remote: u64,
    observed_at: chrono::DateTime<Utc>,
) -> ChannelSnapshot {
    ChannelSnapshot {
        node_id: Some("local-node".into()),
        channel_id: channel_id.into(),
        local_ratio: local as f64 / (local + remote) as f64,
        local_balance_msat: local,
        remote_balance_msat: remote,
        capacity_msat: local + remote,
        status: ChannelStatus::Active,
        ts: observed_at,
        spendable_outbound_msat: local.saturating_sub(10_000),
        spendable_inbound_msat: remote.saturating_sub(10_000),
    }
}

fn seeded_app(auth: Option<&str>) -> (axum::Router, String) {
    seeded_app_at(auth, Utc::now())
}

fn seeded_app_at(auth: Option<&str>, observed_at: chrono::DateTime<Utc>) -> (axum::Router, String) {
    let mut storage = MemoryStorage::new();
    let recommendation = Recommendation {
        finding_id: "finding-1".into(),
        action: Action::for_recommendation(
            "finding-1",
            ActionType::RebalanceChannel,
            Some("c1".into()),
            serde_json::json!({}),
            "review channel",
        ),
        rationale: Rationale {
            evidence: Vec::new(),
            preconditions: Vec::new(),
            expected_effect: String::new(),
            risks: Vec::new(),
            limitations: Vec::new(),
            actionability: Actionability::OperatorActionable,
        },
    };
    storage
        .save_finding(&Finding {
            id: recommendation.finding_id.clone(),
            detector: "channel_liquidity".into(),
            detector_version: "2".into(),
            severity: Severity::Warning,
            schema_version: FINDING_SCHEMA_VERSION,
            node: Some("local-node".into()),
            channel: Some("c1".into()),
            evidence: Vec::new(),
            provenance: Some(FindingProvenance {
                source: ObservationSource::Fixture {
                    redacted_hash: "fixture-hash".into(),
                },
                producers: Vec::new(),
                observation: ObservationReference::ChannelState {
                    channel_id: "c1".into(),
                    snapshot: ChannelSnapshotReference {
                        observed_at,
                        state_digest: "state-hash".into(),
                    },
                },
            }),
            explanation: None,
            timestamp: observed_at,
            first_seen_at: observed_at,
            last_seen_at: observed_at,
            lifecycle: FindingLifecycle::Active,
        })
        .unwrap();
    storage.save_recommendation(&recommendation).unwrap();
    storage
        .save_channel_snapshot(&snapshot("c1", 200_000, 800_000, observed_at))
        .unwrap();
    storage
        .save_channel_snapshot(&snapshot("c2", 700_000, 300_000, observed_at))
        .unwrap();
    let mut api = RiekoApi::new(Box::new(storage)).unwrap();
    if let Some(token) = auth {
        api = api.with_auth(token).unwrap();
    }
    (api.router(), recommendation.action.id)
}

fn request_body(recommendation_id: &str) -> serde_json::Value {
    serde_json::json!({
        "recommendation_id": recommendation_id,
        "model_id": "liquidity-redistribution",
        "source_channel": "c1",
        "destination_channel": "c2",
        "amount_sats": 50
    })
}

async fn post(
    app: &axum::Router,
    body: serde_json::Value,
    token: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v2/simulations")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    app.clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn creates_reuses_and_reports_a_stable_projection() {
    let (app, recommendation_id) = seeded_app(None);
    let response = post(&app, request_body(&recommendation_id), None).await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let created: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let simulation = &created["simulation"];
    let mut keys: Vec<_> = simulation
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "action_type",
            "completed_at",
            "confidence",
            "error_code",
            "finding_id",
            "id",
            "input_hash",
            "model_id",
            "model_version",
            "no_action_executed",
            "parameters",
            "recommendation_id",
            "requested_at",
            "result",
            "source_observed_at",
            "stale",
            "status",
        ]
    );
    assert_eq!(created["reused"], false);
    assert_eq!(simulation["recommendation_id"], recommendation_id);
    assert_eq!(simulation["status"], "completed");
    assert_eq!(simulation["no_action_executed"], true);
    assert!(simulation["result"]["baseline"].is_object());
    assert!(simulation["result"]["projected"].is_object());
    assert!(simulation["result"]["deltas"].is_array());
    assert!(simulation["result"]["assumptions"].is_array());
    assert!(simulation["result"]["warnings"].is_array());

    let reused = post(&app, request_body(&recommendation_id), None).await;
    assert_eq!(reused.status(), StatusCode::OK);
    let bytes = to_bytes(reused.into_body(), 64 * 1024).await.unwrap();
    let reused: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reused["reused"], true);
    assert_eq!(reused["simulation"]["input_hash"], simulation["input_hash"]);

    let id = simulation["id"].as_str().unwrap();
    let report = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v2/simulations/{id}/report"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(report.status(), StatusCode::OK);

    let mut alternative = request_body(&recommendation_id);
    alternative["amount_sats"] = serde_json::json!(60);
    let response = post(&app, alternative, None).await;
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let alternative: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let right_id = alternative["simulation"]["id"].as_str().unwrap();
    let comparison = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v2/simulations/compare")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "left_simulation_id": id,
                        "right_simulation_id": right_id
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(comparison.status(), StatusCode::OK);
    let bytes = to_bytes(comparison.into_body(), 128 * 1024).await.unwrap();
    let comparison: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(comparison["no_action_executed"], true);
    assert!(comparison["projected_local_balance_delta_msat"].is_number());

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v2/simulations?limit=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let bytes = to_bytes(list.into_body(), 128 * 1024).await.unwrap();
    let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn validation_errors_have_stable_codes() {
    let (app, recommendation_id) = seeded_app(None);
    for (body, status, code) in [
        (
            request_body("unknown"),
            StatusCode::NOT_FOUND,
            "recommendation_not_found",
        ),
        (
            serde_json::json!({
                "recommendation_id": recommendation_id,
                "model_id": "arbitrary-plugin",
                "source_channel": "c1",
                "destination_channel": "c2",
                "amount_sats": 50
            }),
            StatusCode::BAD_REQUEST,
            "unknown_model",
        ),
        (
            serde_json::json!({
                "recommendation_id": recommendation_id,
                "model_id": "liquidity-redistribution",
                "source_channel": "c1",
                "destination_channel": "c2",
                "amount_sats": 0
            }),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
    ] {
        let response = post(&app, body, None).await;
        assert_eq!(response.status(), status);
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], code);
    }
}

#[tokio::test]
async fn stale_source_requires_explicit_opt_in_and_remains_marked_stale() {
    let (app, recommendation_id) = seeded_app_at(None, Utc::now() - chrono::Duration::hours(1));
    let body = request_body(&recommendation_id);
    let response = post(&app, body.clone(), None).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(error["error"]["code"], "stale_input");
    assert_eq!(error["error"]["simulation"]["status"], "stale");
    assert!(error["error"]["simulation"]["result"].is_null());

    let mut allowed = body;
    allowed["allow_stale"] = serde_json::json!(true);
    let response = post(&app, allowed, None).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(created["simulation"]["status"], "stale");
    assert_eq!(created["simulation"]["stale"], true);
    assert!(created["simulation"]["result"].is_object());

    let response = post(&app, request_body(&recommendation_id), None).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let mut invalid = request_body(&recommendation_id);
    invalid["allow_stale"] = serde_json::json!(true);
    invalid["amount_sats"] = serde_json::json!(1_000_000);
    let response = post(&app, invalid, None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(error["error"]["code"], "invalid_input");
    assert_eq!(error["error"]["simulation"]["status"], "invalid_input");
}

#[tokio::test]
async fn creation_inherits_authentication() {
    let (app, recommendation_id) = seeded_app(Some("secret"));
    assert_eq!(
        post(&app, request_body(&recommendation_id), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(&app, request_body(&recommendation_id), Some("secret"))
            .await
            .status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn streaming_oversized_simulation_body_is_rejected() {
    let (app, _) = seeded_app(None);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v2/simulations")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b'x'; (1 << 20) + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(error["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn malformed_json_uses_the_stable_error_shape() {
    let (app, _) = seeded_app(None);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v2/simulations")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(error["error"]["code"], "invalid_request");
    assert!(error["error"]["message"].is_string());
}

#[tokio::test]
async fn no_execution_route_is_exposed() {
    let (app, _) = seeded_app(None);
    for uri in [
        "/api/v2/simulations/id/execute",
        "/api/v2/simulations/id/apply",
        "/api/v2/simulations/id/approve",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn missing_simulation_uses_the_stable_error_shape() {
    let (app, _) = seeded_app(None);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v2/simulations/unknown/report")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(error["error"]["code"], "simulation_not_found");
}

#[tokio::test]
async fn comparison_rejects_empty_ids_and_unknown_fields() {
    let (app, _) = seeded_app(None);
    for body in [
        serde_json::json!({
            "left_simulation_id": "",
            "right_simulation_id": ""
        }),
        serde_json::json!({
            "left_simulation_id": "left",
            "right_simulation_id": "right",
            "callback_url": "https://example.invalid"
        }),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/simulations/compare")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_client_error());
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error["error"]["code"], "invalid_request");
    }
}
