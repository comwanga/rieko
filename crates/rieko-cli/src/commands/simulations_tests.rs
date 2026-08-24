use super::*;
use rieko_domain::{BitcoinNetwork, ChannelSnapshot, ChannelStatus};
use rieko_findings::{
    channel_snapshot_state_digest, Action, ActionStage, ActionType, Actionability,
    ChannelSnapshotReference, Evidence, Finding, FindingLifecycle, FindingProvenance,
    ObservationReference, ObservationSource, Rationale, Recommendation, Severity,
    FINDING_SCHEMA_VERSION,
};
use rieko_storage::Storage;

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

fn args(db: PathBuf, recommendation: &Recommendation) -> (SimulationsArgs, CreateArgs) {
    (
        SimulationsArgs {
            command: SimulationCommand::List {
                limit: 1,
                json: false,
            },
            db: Some(db),
        },
        CreateArgs {
            recommendation: recommendation.action.id.clone(),
            model: "liquidity-redistribution".into(),
            source_channel: Some("c1".into()),
            destination_channel: Some("c2".into()),
            amount_sats: Some(50),
            force: false,
            json: false,
        },
    )
}

#[test]
fn create_is_replayable_and_does_not_change_authoritative_records() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("sim.db");
    let recommendation = seed(&db, ActionType::RebalanceChannel);
    let (args, create) = args(db.clone(), &recommendation);
    run_create(&args, &create).unwrap();
    run_create(&args, &create).unwrap();

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
    let (args, create) = args(db.clone(), &recommendation);
    assert!(run_create(&args, &create).is_err());

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
    let (args, create) = args(db.clone(), &recommendation);
    let error = run_create(&args, &create).unwrap_err();
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
    let (args, mut create) = args(db.clone(), &recommendation);
    assert!(run_create(&args, &create).is_err());
    create.force = true;
    run_create(&args, &create).unwrap();

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
    let (args, mut create) = args(db.clone(), &recommendation);
    create.force = true;
    assert!(run_create(&args, &create).is_err());

    let mut storage = SqliteStorage::open(&db).unwrap();
    let record = storage.recent_simulations_v2(1).unwrap().remove(0);
    assert_eq!(record.status, "invalid_input");
    assert!(record.projection.is_null());
}
