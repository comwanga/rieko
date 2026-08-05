use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use rieko_detectors::Detector;
use rieko_domain::ChannelId;
use rieko_findings::{ActionStage, AuditEntry};
use rieko_graph::GraphView;
use rieko_llm::{LlmClient, NullClient, OpenAiCompatibleClient};
use rieko_simulation::Simulator;
use rieko_storage::{SqliteStorage, Storage};
use tracing::{info, warn};

use super::common::{persist_and_recommend, GraphSource};

#[derive(Args, Debug)]
pub struct SimulateArgs {
    /// Path to a JSON fixture matching the LND `/v1/channels` response.
    #[arg(long, value_name = "FILE")]
    fixture: Option<PathBuf>,

    /// LND REST base URL, e.g. `https://localhost:8080`.
    #[arg(long, value_name = "URL", conflicts_with = "fixture")]
    lnd_rest: Option<String>,

    /// Path to a read-only macaroon file for the REST connection.
    #[arg(long, value_name = "FILE")]
    macaroon: Option<PathBuf>,

    /// Local node id (pubkey). Defaults to `local-node`.
    #[arg(long, default_value = "local-node")]
    node: String,

    /// Durable database path. Defaults to `~/.rieko/rieko.db`.
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,
}

/// Run the pipeline once and then project what each recommended action would
/// do to the graph (D7 Simulate). Simulations are read-only and are persisted
/// so the reasoning behind a later approval is on record.
pub fn run(args: SimulateArgs) -> Result<()> {
    let db_path = args.db.clone().unwrap_or_else(default_db_path);
    let mut storage = SqliteStorage::open(&db_path)
        .with_context(|| format!("opening db {}", db_path.display()))?;

    let source = GraphSource {
        fixture: args.fixture.clone(),
        lnd_rest: args.lnd_rest.clone(),
        macaroon: args.macaroon.clone(),
        node: args.node.clone(),
    };
    let graph = source.build()?;
    let (n_nodes, n_channels) = graph.len();
    info!(n_nodes, n_channels, "graph loaded");

    let detector = rieko_detectors::LiquidityDetector::new(args.node.clone());
    let findings = detector.run(&graph, &rieko_detectors::DetectorContext::no_context());
    info!(findings = findings.len(), "detection complete");

    let llm: Box<dyn LlmClient> = OpenAiCompatibleClient::from_env()
        .map(|c| Box::new(c) as Box<dyn LlmClient>)
        .unwrap_or_else(|| Box::new(NullClient));
    let engine = rieko_recommendations::RecommendationEngine;
    let simulator = Simulator;

    let recommendations =
        persist_and_recommend(&mut storage, &*llm, &engine, &args.node, &findings)?;

    let mut n_simulated = 0u64;
    for rec in &recommendations {
        let Some(target) = rec.action.target.as_deref() else {
            continue;
        };
        let Some(channel) = graph.channel(&ChannelId::new(target)) else {
            warn!(target, "no channel in graph for recommendation target");
            continue;
        };
        let sim = match simulator.project(channel, &rec.action, &rec.finding_id) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "simulation skipped");
                continue;
            }
        };
        storage.save_simulation(&sim)?;
        n_simulated += 1;

        // Record the action's progression Recommend → Simulated in the audit log.
        let audit = AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            action_id: rec.action.id.clone(),
            action_type: rec.action.action_type,
            stage: ActionStage::Simulated,
            actor: "system".into(),
            details: serde_json::to_value(&sim.projection).unwrap_or(serde_json::Value::Null),
            timestamp: chrono::Utc::now(),
        };
        storage.append_audit(&audit)?;
    }

    info!(
        recommendations = recommendations.len(),
        simulated = n_simulated,
        "simulation complete"
    );
    print_simulations(&mut storage, 50)?;
    Ok(())
}

fn print_simulations(storage: &mut SqliteStorage, limit: u32) -> Result<()> {
    let sims = storage.recent_simulations(limit)?;
    if sims.is_empty() {
        println!("No simulations on record yet.");
        return Ok(());
    }
    println!("Simulations (newest first):");
    for s in sims {
        println!(
            "  [{}] {} {} -> {} ({} msat, clears: {})",
            s.action_type.as_str(),
            s.id.chars().take(8).collect::<String>(),
            fmt_ratio(s.projection.local_ratio_before),
            fmt_ratio(s.projection.local_ratio_after),
            s.projection.delta_msat,
            if s.projection.clears_finding {
                "yes"
            } else {
                "no"
            },
        );
        println!("      {}", s.projection.summary);
    }
    Ok(())
}

fn fmt_ratio(r: f64) -> String {
    format!("{:.0}%", r * 100.0)
}

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(home).join(".rieko");
    std::fs::create_dir_all(&dir).ok();
    dir.join("rieko.db")
}
