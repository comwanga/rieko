use super::*;
use axum::extract::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::TimeZone;
use rieko_domain::{BitcoinNetwork, ChannelSnapshot, ChannelStatus};
use rieko_findings::{
    channel_snapshot_state_digest, Action, ActionStage, ActionType, Actionability,
    ChannelSnapshotReference, Evidence, Finding, FindingLifecycle, FindingProvenance,
    ObservationReference, ObservationSource, Rationale, Recommendation, Severity,
    FINDING_SCHEMA_VERSION,
};
use rieko_storage::Storage;

fn simulation(id: &str) -> SimulationView {
    use rieko_simulation::model::{
        Assumption, LiquidityRedistributionParameters, ProjectedDelta, ProjectedState,
        SimulationConfidence, SimulationResult, SimulationStatus, SimulationWarning,
    };

    let observed_at = chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    SimulationView {
        id: id.into(),
        recommendation_id: "recommendation-1".into(),
        finding_id: "finding-1".into(),
        action_type: "rebalance_channel".into(),
        status: SimulationStatus::Completed,
        model_id: "liquidity-redistribution".into(),
        model_version: "3".into(),
        input_hash: format!("hash-{id}"),
        parameters: LiquidityRedistributionParameters {
            source_channel: "source-channel".into(),
            destination_channel: "destination-channel".into(),
            amount_msat: 42_000,
        },
        source_observed_at: observed_at,
        stale: false,
        confidence: SimulationConfidence::High,
        result: Some(SimulationResult {
            model_id: "liquidity-redistribution".into(),
            model_version: "3".into(),
            input_hash: format!("hash-{id}"),
            baseline: ProjectedState {
                local_ratio: 0.9,
                local_balance_msat: 900_000,
                remote_balance_msat: 100_000,
                capacity_msat: 1_000_000,
            },
            projected: ProjectedState {
                local_ratio: 0.858,
                local_balance_msat: 858_000,
                remote_balance_msat: 142_000,
                capacity_msat: 1_000_000,
            },
            deltas: vec![ProjectedDelta {
                channel_id: "source-channel".into(),
                local_before_msat: 900_000,
                local_after_msat: 858_000,
                remote_before_msat: 100_000,
                remote_after_msat: 142_000,
                delta_msat: 42_000,
                clears_finding: true,
            }],
            assumptions: vec![Assumption::new("fees_ignored", "Fees are not projected")],
            warnings: vec![SimulationWarning::new(
                "bounded_projection",
                "Projection is local and deterministic",
            )],
            confidence: SimulationConfidence::High,
        }),
        explanation: "Typed deterministic projection".into(),
        error_code: None,
        requested_at: observed_at,
        completed_at: Some(observed_at),
        no_action_executed: true,
    }
}

fn comparison() -> SimulationComparison {
    SimulationComparison {
        recommendation_id: "recommendation-1".into(),
        left: simulation("left"),
        right: simulation("right"),
        projected_local_ratio_delta: 0.1,
        projected_local_balance_delta_msat: 42_000,
        no_action_executed: true,
        freshness_delta_seconds: 0,
        confidence_left: rieko_simulation::model::SimulationConfidence::High,
        confidence_right: rieko_simulation::model::SimulationConfidence::High,
        warnings_left: 1,
        warnings_right: 1,
    }
}

fn authenticated(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some("Bearer simulation-token")
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}

async fn start(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), server)
}

fn api_args(api_url: String, token_file: Option<PathBuf>) -> ApiArgs {
    ApiArgs {
        api_url,
        token_file,
    }
}

#[tokio::test]
async fn read_clients_use_authenticated_api_and_preserve_typed_projection_without_a_database() {
    let app = axum::Router::new()
        .route(
            "/api/v2/simulations",
            get(|headers: HeaderMap| async move {
                if !authenticated(&headers) {
                    return unauthorized();
                }
                Json(vec![simulation("left"), simulation("right")]).into_response()
            }),
        )
        .route(
            "/api/v2/simulations/:simulation_id",
            get(
                |headers: HeaderMap, axum::extract::Path(id): axum::extract::Path<String>| async move {
                    if !authenticated(&headers) {
                        return unauthorized();
                    }
                    Json(simulation(&id)).into_response()
                },
            ),
        )
        .route(
            "/api/v2/simulations/compare",
            post(
                |headers: HeaderMap, Json(command): Json<CompareSimulationsCommand>| async move {
                    if !authenticated(&headers) {
                        return unauthorized();
                    }
                    if command.left_simulation_id != "left"
                        || command.right_simulation_id != "right"
                    {
                        return (StatusCode::BAD_REQUEST, "unexpected comparison ids")
                            .into_response();
                    }
                    Json(comparison()).into_response()
                },
            ),
        );
    let (api_url, server) = start(app).await;
    let directory = tempfile::tempdir().unwrap();
    let token_file = directory.path().join("token");
    let nonexistent_database = directory.path().join("must-not-be-created.db");
    std::fs::write(&token_file, "simulation-token\n").unwrap();
    let client = ApiClient::new(&api_args(api_url, Some(token_file))).unwrap();

    let listed = client.fetch_simulations(2).await.unwrap();
    let shown = client.fetch_simulation("left").await.unwrap();
    let compared = client
        .compare_simulations(&CompareSimulationsCommand {
            left_simulation_id: "left".into(),
            right_simulation_id: "right".into(),
        })
        .await
        .unwrap();

    server.abort();
    assert_eq!(listed, [simulation("left"), simulation("right")]);
    assert_eq!(shown, simulation("left"));
    assert_eq!(compared, comparison());
    let projection = shown.result.unwrap();
    assert_eq!(projection.projected.local_balance_msat, 858_000);
    assert_eq!(projection.deltas[0].channel_id, "source-channel");
    assert_eq!(projection.warnings[0].code, "bounded_projection");
    assert!(!nonexistent_database.exists());
}

#[tokio::test]
async fn read_clients_report_authentication_failure() {
    let app = axum::Router::new().route(
        "/api/v2/simulations",
        get(|headers: HeaderMap| async move {
            if authenticated(&headers) {
                Json(Vec::<SimulationView>::new()).into_response()
            } else {
                unauthorized()
            }
        }),
    );
    let (api_url, server) = start(app).await;

    let error = ApiClient::new(&api_args(api_url, None))
        .unwrap()
        .fetch_simulations(1)
        .await
        .unwrap_err();

    server.abort();
    assert!(error.to_string().contains("401 Unauthorized"));
}

#[tokio::test]
async fn read_clients_report_non_success_and_not_found_responses() {
    let app = axum::Router::new()
        .route(
            "/api/v2/simulations",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "agent unavailable") }),
        )
        .route(
            "/api/v2/simulations/:simulation_id",
            get(|| async { (StatusCode::NOT_FOUND, "simulation not found") }),
        );
    let (api_url, server) = start(app).await;
    let client = ApiClient::new(&api_args(api_url, None)).unwrap();

    let list_error = client.fetch_simulations(1).await.unwrap_err();
    let detail_error = client.fetch_simulation("missing").await.unwrap_err();

    server.abort();
    assert!(list_error.to_string().contains("503 Service Unavailable"));
    assert!(list_error.to_string().contains("agent unavailable"));
    assert!(detail_error.to_string().contains("404 Not Found"));
    assert!(detail_error.to_string().contains("simulation not found"));
}

#[tokio::test]
async fn read_clients_reject_malformed_typed_responses() {
    let app = axum::Router::new()
        .route("/api/v2/simulations", get(|| async { "not simulations" }))
        .route(
            "/api/v2/simulations/:simulation_id",
            get(|| async { "not a simulation" }),
        )
        .route(
            "/api/v2/simulations/compare",
            post(|| async { "not a comparison" }),
        );
    let (api_url, server) = start(app).await;
    let client = ApiClient::new(&api_args(api_url, None)).unwrap();

    let list_error = client.fetch_simulations(1).await.unwrap_err();
    let detail_error = client.fetch_simulation("left").await.unwrap_err();
    let compare_error = client
        .compare_simulations(&CompareSimulationsCommand {
            left_simulation_id: "left".into(),
            right_simulation_id: "right".into(),
        })
        .await
        .unwrap_err();

    server.abort();
    assert!(list_error
        .to_string()
        .contains("decoding typed simulations response"));
    assert!(detail_error
        .to_string()
        .contains("decoding typed simulation response"));
    assert!(compare_error
        .to_string()
        .contains("decoding typed simulation comparison response"));
}

fn recommendation(action_type: ActionType) -> Recommendation {
    Recommendation {
        finding_id: "finding-1".into(),
        action: Action::for_recommendation(
            "finding-1",
            action_type,
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
        lifecycle: None,
    }
}

fn snapshot(
    id: &str,
    local: u64,
    remote: u64,
    ts: chrono::DateTime<chrono::Utc>,
) -> ChannelSnapshot {
    let mut snapshot = ChannelSnapshot {
        node_id: Some("local-node".into()),
        network: Some(BitcoinNetwork::Regtest),
        state_digest: None,
        channel_id: id.into(),
        local_ratio: local as f64 / (local + remote) as f64,
        local_balance_msat: local,
        remote_balance_msat: remote,
        capacity_msat: local + remote,
        status: ChannelStatus::Active,
        ts,
        spendable_outbound_msat: local.saturating_sub(10_000),
        spendable_inbound_msat: remote.saturating_sub(10_000),
    };
    snapshot.state_digest = Some(channel_snapshot_state_digest(&snapshot));
    snapshot
}

fn seed_at(
    db: &std::path::Path,
    action_type: ActionType,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> Recommendation {
    seed_at_with_snapshots(db, action_type, observed_at, true)
}

fn seed_at_with_snapshots(
    db: &std::path::Path,
    action_type: ActionType,
    observed_at: chrono::DateTime<chrono::Utc>,
    include_snapshots: bool,
) -> Recommendation {
    let mut storage = SqliteStorage::open(db).unwrap();
    let recommendation = recommendation(action_type);
    storage
        .save_finding(&Finding {
            id: recommendation.finding_id.clone(),
            detector: "channel_liquidity".into(),
            detector_version: "2".into(),
            severity: Severity::Warning,
            schema_version: FINDING_SCHEMA_VERSION,
            node: Some("local-node".into()),
            channel: Some("c1".into()),
            evidence: vec![Evidence::text("direction", "inbound")],
            provenance: Some(FindingProvenance {
                network: Some(BitcoinNetwork::Regtest),
                source: ObservationSource::Fixture {
                    redacted_hash: "fixture-hash".into(),
                    configured_node: "node-1".into(),
                },
                producers: Vec::new(),
                observation: ObservationReference::ChannelState {
                    channel_id: "c1".into(),
                    snapshot: ChannelSnapshotReference {
                        network: Some(BitcoinNetwork::Regtest),
                        observed_at,
                        state_digest: channel_snapshot_state_digest(&snapshot(
                            "c1",
                            950_000,
                            50_000,
                            observed_at,
                        )),
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
    if include_snapshots {
        storage
            .save_channel_snapshot(&snapshot("c1", 950_000, 50_000, observed_at))
            .unwrap();
        storage
            .save_channel_snapshot(&snapshot("c2", 200_000, 800_000, observed_at))
            .unwrap();
    }
    recommendation
}

fn seed(db: &std::path::Path, action_type: ActionType) -> Recommendation {
    seed_at(db, action_type, chrono::Utc::now())
}

fn args(db: PathBuf, recommendation: &Recommendation) -> CreateArgs {
    CreateArgs {
        db: Some(db),
        recommendation: recommendation.action.id.clone(),
        model: "liquidity-redistribution".into(),
        source_channel: Some("c1".into()),
        destination_channel: Some("c2".into()),
        amount_sats: Some(50),
        force: false,
        json: false,
    }
}

#[test]
fn create_is_replayable_and_does_not_change_authoritative_records() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("sim.db");
    let recommendation = seed(&db, ActionType::RebalanceChannel);
    let create = args(db.clone(), &recommendation);
    run_create(&create).unwrap();
    run_create(&create).unwrap();

    let mut storage = SqliteStorage::open(&db).unwrap();
    let records = storage.recent_simulations_v2(10).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, "completed");
    assert_eq!(storage.simulation_events(&records[0].id).unwrap().len(), 2);
    assert_eq!(storage.latest_findings(10).unwrap().len(), 1);
    assert_eq!(storage.latest_recommendations(10).unwrap().len(), 1);
    assert_eq!(
        storage
            .recommendation_for_action(&recommendation.action.id)
            .unwrap()
            .unwrap()
            .action
            .stage,
        ActionStage::Recommended
    );
    assert!(storage.recent_audit(10).unwrap().is_empty());
}

#[test]
fn unsupported_recommendation_is_persisted_without_projection() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("unsupported.db");
    let recommendation = seed(&db, ActionType::UpdateFeePolicy);
    let create = args(db.clone(), &recommendation);
    assert!(run_create(&create).is_err());

    let mut storage = SqliteStorage::open(&db).unwrap();
    let record = storage.recent_simulations_v2(1).unwrap().remove(0);
    assert_eq!(record.status, "unsupported");
    assert_eq!(
        record.error_code.as_deref(),
        Some("unsupported_recommendation")
    );
    assert!(record.projection.is_null());
    assert_eq!(storage.simulation_events(&record.id).unwrap().len(), 2);
}

#[test]
fn unsupported_recommendation_precedes_missing_snapshot_context() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("unsupported-no-context.db");
    let recommendation =
        seed_at_with_snapshots(&db, ActionType::UpdateFeePolicy, chrono::Utc::now(), false);
    let create = args(db.clone(), &recommendation);
    let error = run_create(&create).unwrap_err();
    let app_error = error
        .downcast_ref::<rieko_simulation_app::SimulationAppError>()
        .unwrap();
    assert_eq!(
        app_error.kind,
        rieko_simulation_app::SimulationAppErrorKind::UnsupportedRecommendation
    );

    let mut storage = SqliteStorage::open(&db).unwrap();
    assert!(storage.recent_simulations_v2(1).unwrap().is_empty());
}

#[test]
fn force_can_calculate_after_a_stale_refusal() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("stale.db");
    let recommendation = seed_at(
        &db,
        ActionType::RebalanceChannel,
        chrono::Utc::now() - chrono::Duration::hours(1),
    );
    let mut create = args(db.clone(), &recommendation);
    assert!(run_create(&create).is_err());
    create.force = true;
    run_create(&create).unwrap();

    let mut storage = SqliteStorage::open(&db).unwrap();
    let records = storage.recent_simulations_v2(10).unwrap();
    assert_eq!(records.len(), 2);
    let completed = storage
        .simulation_v2_by_input_hash(&records[0].input_hash)
        .unwrap()
        .unwrap();
    assert_eq!(completed.status, "stale");
    assert!(!completed.projection.is_null());
}

#[test]
fn force_does_not_accept_future_dated_observations() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("future.db");
    let recommendation = seed_at(
        &db,
        ActionType::RebalanceChannel,
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let mut create = args(db.clone(), &recommendation);
    create.force = true;
    assert!(run_create(&create).is_err());

    let mut storage = SqliteStorage::open(&db).unwrap();
    let record = storage.recent_simulations_v2(1).unwrap().remove(0);
    assert_eq!(record.status, "invalid_input");
    assert!(record.projection.is_null());
}
