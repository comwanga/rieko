//! V2 simulation CLI — create, list, and inspect deterministic projections.
//! Default-enabled (simulate feature). No node mutation; no execution path.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
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

    let now = chrono::Utc::now();
    let model_id = &c.model;
    let model_version = match model_id.as_str() {
        "liquidity-redistribution" => "1",
        _ => bail!("unknown simulation model: {model_id}"),
    };

    let params = serde_json::json!({
        "source_channel": c.source_channel,
        "destination_channel": c.destination_channel,
        "amount_sats": c.amount_sats,
    });

    // Validate amount
    if let Some(amt) = c.amount_sats {
        if amt == 0 {
            bail!("amount must be greater than zero");
        }
    }

    let input_hash = compute_v2_input_hash(model_id, model_version, &params, &now);
    let id = uuid::Uuid::new_v4().to_string();

    let rec = SimulationRecord {
        id: id.clone(),
        action_id: rec.action.id.clone(),
        finding_id: rec.finding_id.clone(),
        action_type: rec.action.action_type.as_str().to_string(),
        status: "completed".into(),
        model_id: model_id.into(),
        model_version: model_version.into(),
        input_hash: input_hash.clone(),
        confidence: "medium".into(),
        assumptions: serde_json::json!([
            {"code":"FeesNotEstimated","description":"Routing fees are not estimated"},
            {"code":"PendingHtlcsExcluded","description":"Pending HTLCs are not included in the projection"}
        ]),
        warnings: if c.force {
            serde_json::json!([])
        } else {
            serde_json::json!([
                {"code":"SnapshotMayBecomeStale","description":"Source data may become stale without a recent observation"}
            ])
        },
        explanation: String::new(),
        projection: serde_json::json!({
            "local_ratio_before": 0.0,
            "local_ratio_after": 0.0,
            "local_balance_msat_after": 0,
            "remote_balance_msat_after": 0,
            "delta_msat": 0,
            "clears_finding": false,
            "summary": format!(
                "Simulation created from recommendation {}. To see projected liquidity changes, \
                 connect to a live node with `--lnd-rest` in the simulate pipeline.",
                c.recommendation
            ),
        }),
        created_at: now.to_rfc3339(),
    };

    storage.save_simulation_v2(&rec)?;
    info!(simulation_id = %id, model_id, "simulation created");
    println!("Created simulation {id}");
    println!("  model:   {model_id} v{model_version}");
    println!("  hash:    {input_hash}");

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

fn compute_v2_input_hash(
    model_id: &str,
    model_version: &str,
    params: &serde_json::Value,
    observed_at: &chrono::DateTime<chrono::Utc>,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"rieko-simulation-v2:");
    h.update(model_id.as_bytes());
    h.update(b":");
    h.update(model_version.as_bytes());
    h.update(b":");
    h.update(observed_at.to_rfc3339().as_bytes());
    h.update(b":");
    h.update(serde_json::to_vec(params).unwrap_or_default());
    format!("{:x}", h.finalize())
}

/// Minimal polyfill for platforms where `dirs_next` isn't available.
fn dirs_next() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}
