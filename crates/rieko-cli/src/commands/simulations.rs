//! V2 simulation CLI — create, list, and inspect deterministic projections.
//! Default-enabled (simulate feature). No node mutation; no execution path.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use rieko_domain::ChannelId;
use rieko_simulation::model::{
    compute_input_hash, LiquidityRedistributionModel, SimulationContext, SimulationModel,
    SimulationRequest,
};
use rieko_storage::{SimulationRecord, SqliteStorage, Storage};
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
    /// Ignore stale snapshot warning.
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
    let rec = storage
        .recommendation_for_action(&c.recommendation)?
        .with_context(|| format!("no recommendation with id {}", c.recommendation))?;

    let mut source_observed_at = chrono::Utc::now(); // default, overwritten from snapshot
    let model_id = &c.model;
    let model_version = match model_id.as_str() {
        "liquidity-redistribution" => "1",
        _ => bail!("unknown simulation model: {model_id}"),
    };

    // Build parameters
    let params = serde_json::json!({
        "source_channel": c.source_channel,
        "destination_channel": c.destination_channel,
        "amount_sats": c.amount_sats,
    });

    if let Some(amt) = c.amount_sats {
        if amt == 0 {
            bail!("amount must be greater than zero");
        }
    }

    let id = uuid::Uuid::new_v4().to_string();

    // Build simulation context from persisted channel snapshots
    let mut channels = std::collections::HashMap::new();
    if c.source_channel.is_some() || c.destination_channel.is_some() {
        let snaps = storage.recent_snapshots_all(500)?;
        source_observed_at = snaps.first().map(|s| s.ts).unwrap_or(source_observed_at);
        // Reconstruct approximate channel state from most recent snapshot per channel
        let mut seen: std::collections::HashMap<ChannelId, bool> = std::collections::HashMap::new();
        for snap in snaps {
            let cid = snap.channel_id();
            if !seen.contains_key(&cid) {
                seen.insert(cid.clone(), true);
                channels.insert(
                    cid.clone(),
                    rieko_domain::Channel {
                        id: cid,
                        node: rieko_domain::NodeId::new("local-node"),
                        peer: rieko_domain::NodeId::new("unknown"),
                        channel_point: String::new(),
                        capacity_msat: snap.capacity_msat,
                        fee_policy: rieko_domain::FeePolicy::default(),
                        status: snap.status,
                        liquidity: rieko_domain::LiquidityProfile::compute(
                            snap.capacity_msat,
                            snap.local_balance_msat,
                            snap.remote_balance_msat,
                        ),
                        last_seen: snap.ts,
                        opening_height: None,
                        local_reserve_msat: None,
                        remote_reserve_msat: None,
                        is_private: false,
                        is_initiator: false,
                        total_sent_msat: None,
                        total_received_msat: None,
                    },
                );
            }
        }
    }

    let snapshot_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        let mut sorted: std::collections::BTreeMap<&ChannelId, &rieko_domain::Channel> =
            std::collections::BTreeMap::new();
        for (cid, ch) in channels.iter() {
            sorted.insert(cid, ch);
        }
        for (cid, ch) in &sorted {
            h.update(cid.as_str().as_bytes());
            h.update(ch.liquidity.local_balance_msat.to_be_bytes());
            h.update(ch.liquidity.remote_balance_msat.to_be_bytes());
            h.update(ch.capacity_msat.to_be_bytes());
        }
        format!("{:x}", h.finalize())
    };

    let ctx = SimulationContext { channels };
    let request = SimulationRequest {
        id: id.clone(),
        recommendation_id: c.recommendation.clone(),
        finding_id: rec.finding_id.clone(),
        model_id: model_id.into(),
        model_version: model_version.into(),
        source_observed_at,
        source_snapshot_hash: snapshot_hash.clone(),
        parameters: params.clone(),
        requested_at: chrono::Utc::now(),
    };

    let input_hash = compute_input_hash(
        model_id,
        model_version,
        &params,
        &source_observed_at,
        &snapshot_hash,
    );

    // Run the model
    let model = LiquidityRedistributionModel::new();
    let result = model.simulate(&request, &ctx)?;

    let status = result.status.as_str().to_string();
    let confidence = result.confidence.as_str().to_string();
    let assumptions: Vec<_> = result
        .assumptions
        .iter()
        .map(|a| serde_json::json!({"code": a.code, "description": a.description}))
        .collect();
    let warnings: Vec<_> = result
        .warnings
        .iter()
        .map(|w| serde_json::json!({"code": w.code, "description": w.description}))
        .collect();
    let explanation = result.explanation.clone();
    let projection = serde_json::to_value(&result).unwrap_or_default();

    let rec = SimulationRecord {
        id: id.clone(),
        action_id: rec.action.id.clone(),
        finding_id: rec.finding_id.clone(),
        action_type: rec.action.action_type.as_str().to_string(),
        status,
        model_id: model_id.into(),
        model_version: model_version.into(),
        input_hash,
        confidence,
        assumptions: serde_json::Value::Array(assumptions),
        warnings: serde_json::Value::Array(warnings),
        explanation: explanation.unwrap_or_default(),
        projection,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    storage.save_simulation_v2(&rec)?;
    info!(simulation_id = %id, model_id, "simulation created");
    println!("Created simulation {id}");
    println!("  model:   {model_id} v{model_version}");
    println!("  hash:    {}", rec.input_hash);

    Ok(())
}

fn run_list(args: &SimulationsArgs, limit: u32) -> Result<()> {
    let mut storage = open(args)?;
    let recs = storage.recent_simulations_v2(limit)?;
    if recs.is_empty() {
        println!("No simulations on record.");
        return Ok(());
    }
    for rec in recs {
        println!(
            "{:<12} {:12} {:12} {}",
            rec.id.chars().take(12).collect::<String>(),
            rec.model_id,
            rec.status,
            rec.created_at
        );
    }
    Ok(())
}

fn run_show(args: &SimulationsArgs, simulation_id: &str) -> Result<()> {
    let mut storage = open(args)?;
    let recs = storage.recent_simulations_v2(1000)?;
    let rec = recs
        .iter()
        .find(|r| r.id == simulation_id)
        .with_context(|| format!("no simulation with id {simulation_id}"))?;

    println!("Simulation {simulation_id}");
    println!("  recommendation: {}", rec.action_id);
    println!("  model:          {} v{}", rec.model_id, rec.model_version);
    println!("  status:         {}", rec.status);
    println!("  confidence:     {}", rec.confidence);
    println!("  input hash:     {}", rec.input_hash);
    println!("  created:        {}", rec.created_at);

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

/// Minimal polyfill for platforms where `dirs_next` isn't available.
fn dirs_next() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}
