//! V2 simulation CLI — create, list, and inspect deterministic projections.
//! Default-enabled (simulate feature). No node mutation; no execution path.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use rieko_simulation::model::{
    compute_input_hash, LiquidityRedistributionModel, LiquidityRedistributionParameters,
    ModelError, SimulationInput, SimulationModel, SimulationResult, SimulationStatus,
    DEFAULT_FRESHNESS,
};
use rieko_storage::{SimulationEvent, SimulationRecord, SqliteStorage, Storage};
use tracing::info;

/// Create and inspect deterministic what-if projections (v2).
#[derive(Args, Debug)]
pub struct SimulationsArgs {
    #[command(subcommand)]
    command: SimulationCommand,

    /// Durable database path. Defaults to `~/.rieko/rieko.db`.
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum SimulationCommand {
    /// Create a new simulation from a recommendation.
    Create(CreateArgs),
    /// List recent simulation results.
    List {
        #[arg(long, default_value_t = 25)]
        limit: u32,
    },
    /// Show a specific simulation by ID.
    Show { simulation_id: String },
}

#[derive(Args, Debug)]
struct CreateArgs {
    /// Recommendation action ID to simulate.
    #[arg(long)]
    recommendation: String,
    /// Model to use (e.g. 'liquidity-redistribution').
    #[arg(long, default_value = "liquidity-redistribution")]
    model: String,
    /// Source channel ID.
    #[arg(long)]
    source_channel: Option<String>,
    /// Destination channel ID.
    #[arg(long)]
    destination_channel: Option<String>,
    /// Hypothetical amount in satoshis.
    #[arg(long)]
    amount_sats: Option<u64>,
    /// Calculate from stale snapshots but keep the result marked stale.
    #[arg(long)]
    force: bool,
}

fn default_db_path() -> PathBuf {
    let home = dirs_next().unwrap_or_else(|| PathBuf::from("."));
    home.join(".rieko").join("rieko.db")
}

fn open(args: &SimulationsArgs) -> Result<SqliteStorage> {
    let db_path = args.db.clone().unwrap_or_else(default_db_path);
    SqliteStorage::open(&db_path).with_context(|| format!("opening db {}", db_path.display()))
}

pub fn run(args: SimulationsArgs) -> Result<()> {
    match &args.command {
        SimulationCommand::Create(c) => run_create(&args, c),
        SimulationCommand::List { limit } => run_list(&args, *limit),
        SimulationCommand::Show { simulation_id } => run_show(&args, simulation_id),
    }
}

fn run_create(args: &SimulationsArgs, c: &CreateArgs) -> Result<()> {
    let mut storage = open(args)?;
    let recommendation = storage
        .recommendation_for_action(&c.recommendation)?
        .with_context(|| format!("no recommendation with id {}", c.recommendation))?;
    let finding = storage
        .finding_by_id(&recommendation.finding_id)?
        .with_context(|| format!("no finding with id {}", recommendation.finding_id))?;
    if finding.lifecycle != rieko_findings::FindingLifecycle::Active {
        bail!("finding {} is not active", finding.id);
    }
    let node_id = finding
        .node
        .clone()
        .filter(|node| !node.trim().is_empty())
        .context("finding has no node identity")?;
    let provenance = finding
        .provenance
        .clone()
        .context("finding has no observation provenance")?;
    let finding_channel = finding
        .channel
        .clone()
        .filter(|channel| !channel.trim().is_empty())
        .context("finding has no channel identity")?;
    let recommendation_target = recommendation
        .action
        .target
        .clone()
        .filter(|target| !target.trim().is_empty())
        .context("recommendation has no channel target")?;
    let model = LiquidityRedistributionModel::new();
    if c.model != model.model_id() {
        bail!("unknown simulation model: {}", c.model);
    }
    let source_channel = required(c.source_channel.as_deref(), "source_channel")?;
    let destination_channel = required(c.destination_channel.as_deref(), "destination_channel")?;
    let amount_msat = c
        .amount_sats
        .context("amount_sats required")?
        .checked_mul(1_000)
        .context("amount_sats is too large")?;
    let source_snapshot = storage
        .recent_channel_snapshots_for_node(&node_id, source_channel, 1)?
        .into_iter()
        .next()
        .with_context(|| format!("no snapshot for source channel {source_channel}"))?;
    let destination_snapshot = storage
        .recent_channel_snapshots_for_node(&node_id, destination_channel, 1)?
        .into_iter()
        .next()
        .with_context(|| format!("no snapshot for destination channel {destination_channel}"))?;
    let input = SimulationInput {
        recommendation_id: recommendation.action.id.clone(),
        recommendation_target,
        finding_id: recommendation.finding_id.clone(),
        finding_channel,
        node_id,
        provenance,
        action_type: recommendation.action.action_type,
        model_id: model.model_id().into(),
        model_version: model.model_version().into(),
        parameters: LiquidityRedistributionParameters {
            source_channel: source_channel.into(),
            destination_channel: destination_channel.into(),
            amount_msat,
        },
        source_snapshot,
        destination_snapshot,
    };
    let input_hash = compute_input_hash(&input)?;
    if let Some(existing) = storage.simulation_v2_by_input_hash(&input_hash)? {
        if !existing.projection.is_null() {
            println!("Reusing simulation {} for identical input", existing.id);
            return Ok(());
        }
        if !(c.force && existing.status == "stale") {
            bail!(
                "identical simulation request {} already ended with status {}",
                existing.id,
                existing.status
            );
        }
    }

    let requested_at = chrono::Utc::now();
    let stale = input.is_stale_at(requested_at, DEFAULT_FRESHNESS);
    let future = input.is_future_at(requested_at);
    let outcome = if !model.supports(&recommendation) {
        Err(ModelError::Unsupported {
            model_id: model.model_id().into(),
        })
    } else if future {
        Err(ModelError::InvalidInput(
            "source snapshots are dated after the simulation request".into(),
        ))
    } else if stale && !c.force {
        Err(ModelError::InvalidInput(
            "source snapshots are stale; inspect them before using --force".into(),
        ))
    } else {
        model.simulate(&input)
    };
    let id = uuid::Uuid::new_v4().to_string();
    let (status, result, error_code, error_message) = match outcome {
        Ok(result) if stale => (SimulationStatus::Stale, Some(result), None, None),
        Ok(result) => (SimulationStatus::Completed, Some(result), None, None),
        Err(ModelError::Unsupported { .. }) => (
            SimulationStatus::Unsupported,
            None,
            Some("unsupported_recommendation".to_string()),
            Some("recommendation type is unsupported by this model".to_string()),
        ),
        Err(ModelError::InvalidInput(message)) => (
            if stale {
                SimulationStatus::Stale
            } else {
                SimulationStatus::InvalidInput
            },
            None,
            Some(
                if stale {
                    "stale_input"
                } else {
                    "invalid_input"
                }
                .to_string(),
            ),
            Some(message),
        ),
        Err(error) => (
            SimulationStatus::Failed,
            None,
            Some("model_failure".to_string()),
            Some(error.to_string()),
        ),
    };
    let record = simulation_record(
        &id,
        &recommendation,
        &input,
        &input_hash,
        status,
        result.as_ref(),
        requested_at,
        chrono::Utc::now(),
        error_code.clone(),
    )?;
    persist_simulation_outcome(&mut storage, &record, error_code)?;

    info!(simulation_id = %id, status = status.as_str(), "simulation recorded");
    println!("Simulation {id}");
    println!("  model:   {} v{}", model.model_id(), model.model_version());
    println!("  status:  {}", status.as_str());
    println!("  hash:    {input_hash}");
    println!("  source:  {}", input.observed_at().to_rfc3339());
    println!("  No action was executed.");
    if let Some(message) = error_message {
        bail!(message);
    }
    Ok(())
}

fn required<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str> {
    value
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("{name} required"))
}

#[allow(clippy::too_many_arguments)]
fn simulation_record(
    id: &str,
    recommendation: &rieko_findings::Recommendation,
    input: &SimulationInput,
    input_hash: &str,
    status: SimulationStatus,
    result: Option<&SimulationResult>,
    requested_at: chrono::DateTime<chrono::Utc>,
    completed_at: chrono::DateTime<chrono::Utc>,
    error_code: Option<String>,
) -> Result<SimulationRecord> {
    let assumptions = result
        .map(|result| serde_json::to_value(&result.assumptions))
        .transpose()?
        .unwrap_or_else(|| serde_json::json!([]));
    let warnings = result
        .map(|result| serde_json::to_value(&result.warnings))
        .transpose()?
        .unwrap_or_else(|| serde_json::json!([]));
    Ok(SimulationRecord {
        id: id.into(),
        action_id: recommendation.action.id.clone(),
        finding_id: recommendation.finding_id.clone(),
        action_type: recommendation.action.action_type.as_str().into(),
        status: status.as_str().into(),
        model_id: input.model_id.clone(),
        model_version: input.model_version.clone(),
        input_hash: input_hash.into(),
        confidence: result
            .map(|result| result.confidence.as_str())
            .unwrap_or("unknown")
            .into(),
        assumptions,
        warnings,
        explanation: String::new(),
        canonical_input: serde_json::to_value(input)?,
        projection: result
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or(serde_json::Value::Null),
        source_observed_at: Some(input.observed_at().to_rfc3339()),
        requested_at: requested_at.to_rfc3339(),
        completed_at: Some(completed_at.to_rfc3339()),
        error_code,
        created_at: requested_at.to_rfc3339(),
    })
}

fn persist_simulation_outcome(
    storage: &mut impl Storage,
    record: &SimulationRecord,
    error_code: Option<String>,
) -> Result<()> {
    storage.begin_transaction()?;
    let result = (|| {
        storage.save_simulation_v2(record)?;
        for (status, error_code, timestamp) in [
            (
                SimulationStatus::Requested,
                None,
                record.requested_at.clone(),
            ),
            (
                match record.status.as_str() {
                    "completed" => SimulationStatus::Completed,
                    "unsupported" => SimulationStatus::Unsupported,
                    "invalid_input" => SimulationStatus::InvalidInput,
                    "stale" => SimulationStatus::Stale,
                    _ => SimulationStatus::Failed,
                },
                error_code,
                record
                    .completed_at
                    .clone()
                    .unwrap_or_else(|| record.requested_at.clone()),
            ),
        ] {
            storage.append_simulation_event(&SimulationEvent {
                id: uuid::Uuid::new_v4().to_string(),
                simulation_id: record.id.clone(),
                status: status.as_str().into(),
                error_code,
                timestamp,
            })?;
        }
        Ok::<_, anyhow::Error>(())
    })();
    match result {
        Ok(()) => storage.commit_transaction().map_err(Into::into),
        Err(error) => {
            let _ = storage.rollback_transaction();
            Err(error)
        }
    }
}

fn run_list(args: &SimulationsArgs, limit: u32) -> Result<()> {
    let mut storage = open(args)?;
    let recs = storage.recent_simulations_v2(limit)?;
    if recs.is_empty() {
        println!("No simulations on record.");
        return Ok(());
    }
    for rec in recs {
        let status = effective_status(&rec);
        println!(
            "{:<12} {:12} {:12} {}",
            rec.id.chars().take(12).collect::<String>(),
            rec.model_id,
            status,
            rec.created_at
        );
    }
    Ok(())
}

fn run_show(args: &SimulationsArgs, simulation_id: &str) -> Result<()> {
    let mut storage = open(args)?;
    let rec = storage
        .simulation_v2_by_id(simulation_id)?
        .with_context(|| format!("no simulation with id {simulation_id}"))?;

    println!("Simulation {simulation_id}");
    println!("  recommendation: {}", rec.action_id);
    println!("  model:          {} v{}", rec.model_id, rec.model_version);
    println!("  status:         {}", effective_status(&rec));
    println!("  confidence:     {}", rec.confidence);
    println!("  input hash:     {}", rec.input_hash);
    println!("  created:        {}", rec.created_at);
    if let Some(source) = &rec.source_observed_at {
        println!("  source:         {source}");
    }
    println!("  No action was executed.");

    if !rec.explanation.is_empty() {
        println!();
        println!("  Explanation:");
        println!("  {}", rec.explanation);
    }

    if let Some(arr) = rec.assumptions.as_array() {
        if !arr.is_empty() {
            println!();
            println!("  Assumptions:");
            for a in arr {
                println!(
                    "    [{}] {}",
                    a["code"].as_str().unwrap_or("?"),
                    a["description"].as_str().unwrap_or("?")
                );
            }
        }
    }

    if let Some(arr) = rec.warnings.as_array() {
        if !arr.is_empty() {
            println!();
            println!("  Warnings:");
            for w in arr {
                println!(
                    "    [{}] {}",
                    w["code"].as_str().unwrap_or("?"),
                    w["description"].as_str().unwrap_or("?")
                );
            }
        }
    }

    Ok(())
}

fn effective_status(record: &SimulationRecord) -> &str {
    if record.status == "completed"
        && record
            .source_observed_at
            .as_deref()
            .is_some_and(|timestamp| {
                chrono::DateTime::parse_from_rfc3339(timestamp)
                    .map(|observed_at| {
                        chrono::Utc::now()
                            .signed_duration_since(observed_at.with_timezone(&chrono::Utc))
                            > DEFAULT_FRESHNESS
                    })
                    .unwrap_or(false)
            })
    {
        "stale"
    } else {
        &record.status
    }
}

/// Minimal polyfill for platforms where `dirs_next` isn't available.
fn dirs_next() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rieko_domain::{ChannelSnapshot, ChannelStatus};
    use rieko_findings::{
        Action, ActionStage, ActionType, Actionability, ChannelSnapshotReference, Finding,
        FindingLifecycle, FindingProvenance, ObservationReference, ObservationSource, Rationale,
        Recommendation, Severity, FINDING_SCHEMA_VERSION,
    };

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
        }
    }

    fn snapshot(
        id: &str,
        local: u64,
        remote: u64,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> ChannelSnapshot {
        ChannelSnapshot {
            node_id: Some("local-node".into()),
            channel_id: id.into(),
            local_ratio: local as f64 / (local + remote) as f64,
            local_balance_msat: local,
            remote_balance_msat: remote,
            capacity_msat: local + remote,
            status: ChannelStatus::Active,
            ts,
            spendable_outbound_msat: local.saturating_sub(10_000),
            spendable_inbound_msat: remote.saturating_sub(10_000),
        }
    }

    fn seed(db: &std::path::Path, action_type: ActionType) -> Recommendation {
        seed_at(db, action_type, chrono::Utc::now())
    }

    fn seed_at(
        db: &std::path::Path,
        action_type: ActionType,
        observed_at: chrono::DateTime<chrono::Utc>,
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
        recommendation
    }

    fn args(db: PathBuf, recommendation: &Recommendation) -> (SimulationsArgs, CreateArgs) {
        (
            SimulationsArgs {
                command: SimulationCommand::List { limit: 1 },
                db: Some(db),
            },
            CreateArgs {
                recommendation: recommendation.action.id.clone(),
                model: "liquidity-redistribution".into(),
                source_channel: Some("c1".into()),
                destination_channel: Some("c2".into()),
                amount_sats: Some(50),
                force: false,
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
}
