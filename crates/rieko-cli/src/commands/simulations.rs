//! Create, inspect, and compare deterministic local projections.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use rieko_simulation_app::{
    compare_simulations, create_simulation, get_simulation, list_simulations,
    CompareSimulationsCommand, CreateSimulationCommand, SimulationComparison, SimulationView,
};
use rieko_storage::SqliteStorage;

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
    /// Create a simulation from a recommendation.
    Create(CreateArgs),
    /// List recent simulations.
    List {
        #[arg(long, default_value_t = 25)]
        limit: u32,
        /// Emit the complete machine-readable response.
        #[arg(long)]
        json: bool,
    },
    /// Show a simulation by ID.
    Show {
        simulation_id: String,
        /// Emit the complete machine-readable response.
        #[arg(long)]
        json: bool,
    },
    /// Compare two compatible completed projections.
    Compare {
        left_simulation_id: String,
        right_simulation_id: String,
        /// Emit the complete machine-readable response.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args, Debug)]
struct CreateArgs {
    /// Recommendation action ID to simulate.
    #[arg(long)]
    recommendation: String,
    /// Model to use.
    #[arg(long, default_value = "liquidity-redistribution")]
    model: String,
    #[arg(long)]
    source_channel: Option<String>,
    #[arg(long)]
    destination_channel: Option<String>,
    /// Hypothetical amount in satoshis.
    #[arg(long)]
    amount_sats: Option<u64>,
    /// Calculate from stale snapshots but keep the result marked stale.
    #[arg(long)]
    force: bool,
    /// Emit the complete machine-readable response.
    #[arg(long)]
    json: bool,
}

pub fn run(args: SimulationsArgs) -> Result<()> {
    match &args.command {
        SimulationCommand::Create(create) => run_create(&args, create),
        SimulationCommand::List { limit, json } => run_list(&args, *limit, *json),
        SimulationCommand::Show {
            simulation_id,
            json,
        } => run_show(&args, simulation_id, *json),
        SimulationCommand::Compare {
            left_simulation_id,
            right_simulation_id,
            json,
        } => run_compare(&args, left_simulation_id, right_simulation_id, *json),
    }
}

fn run_create(args: &SimulationsArgs, create: &CreateArgs) -> Result<()> {
    let source_channel = create
        .source_channel
        .as_deref()
        .context("--source-channel is required for this model")?;
    let destination_channel = create
        .destination_channel
        .as_deref()
        .context("--destination-channel is required for this model")?;
    let amount_sats = create
        .amount_sats
        .context("--amount-sats is required for this model")?;
    let mut storage = open(args)?;
    let outcome = create_simulation(
        &mut storage,
        CreateSimulationCommand {
            recommendation_id: create.recommendation.clone(),
            model_id: create.model.clone(),
            source_channel: source_channel.into(),
            destination_channel: destination_channel.into(),
            amount_sats,
            allow_stale: create.force,
        },
    )
    .map_err(anyhow::Error::new)?;
    if create.json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
        return Ok(());
    }
    if outcome.reused {
        println!("Reusing simulation {}", outcome.simulation.id);
    }
    print_simulation(&outcome.simulation)
}

fn run_list(args: &SimulationsArgs, limit: u32, json: bool) -> Result<()> {
    let mut storage = open(args)?;
    let simulations = list_simulations(&mut storage, limit).map_err(anyhow::Error::new)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&simulations)?);
        return Ok(());
    }
    if simulations.is_empty() {
        println!("No simulations on record.");
        return Ok(());
    }
    for simulation in simulations {
        println!(
            "{:<12} {:24} {:12} {}",
            simulation.id.chars().take(12).collect::<String>(),
            simulation.model_id,
            simulation.status.as_str(),
            simulation.requested_at
        );
    }
    Ok(())
}

fn run_show(args: &SimulationsArgs, simulation_id: &str, json: bool) -> Result<()> {
    let mut storage = open(args)?;
    let simulation = get_simulation(&mut storage, simulation_id)
        .map_err(anyhow::Error::new)?
        .with_context(|| format!("no simulation with id {simulation_id}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&simulation)?);
        Ok(())
    } else {
        print_simulation(&simulation)
    }
}

fn run_compare(
    args: &SimulationsArgs,
    left_simulation_id: &str,
    right_simulation_id: &str,
    json: bool,
) -> Result<()> {
    let mut storage = open(args)?;
    let comparison = compare_simulations(
        &mut storage,
        CompareSimulationsCommand {
            left_simulation_id: left_simulation_id.into(),
            right_simulation_id: right_simulation_id.into(),
        },
    )
    .map_err(anyhow::Error::new)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&comparison)?);
    } else {
        print_comparison(&comparison);
    }
    Ok(())
}

fn print_simulation(simulation: &SimulationView) -> Result<()> {
    println!("Simulation {}", simulation.id);
    println!("  recommendation: {}", simulation.recommendation_id);
    println!(
        "  model:          {} v{}",
        simulation.model_id, simulation.model_version
    );
    println!("  status:         {}", simulation.status.as_str());
    println!("  confidence:     {}", simulation.confidence.as_str());
    println!("  input hash:     {}", simulation.input_hash);
    println!("  requested:      {}", simulation.requested_at);
    println!("  source:         {}", simulation.source_observed_at);
    println!("  stale:          {}", simulation.stale);
    println!(
        "  parameters:     {}",
        serde_json::to_string(&simulation.parameters)?
    );
    if let Some(result) = &simulation.result {
        println!();
        println!("{}", serde_json::to_string_pretty(result)?);
    }
    println!("  No action was executed.");
    Ok(())
}

fn print_comparison(comparison: &SimulationComparison) {
    println!(
        "Simulation comparison {} -> {}",
        comparison.left.id, comparison.right.id
    );
    println!("  recommendation: {}", comparison.recommendation_id);
    println!(
        "  projected local ratio delta: {:.6}",
        comparison.projected_local_ratio_delta
    );
    println!(
        "  projected local balance delta: {} msat",
        comparison.projected_local_balance_delta_msat
    );
    println!("  No action was executed.");
}

fn open(args: &SimulationsArgs) -> Result<SqliteStorage> {
    let db_path = args.db.clone().unwrap_or_else(default_db_path);
    SqliteStorage::open(&db_path).with_context(|| format!("opening db {}", db_path.display()))
}

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".rieko").join("rieko.db")
}

#[cfg(test)]
#[path = "simulations_tests.rs"]
mod tests;
