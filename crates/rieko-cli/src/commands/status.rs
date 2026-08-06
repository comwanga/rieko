use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Args;
use rieko_status::{assess, HealthPolicy, OperationalState, OperationalStateStore};
use rieko_storage::{SqliteStorage, Storage, CURRENT_SCHEMA_VERSION};
use tracing::info;

#[derive(Args, Debug)]
pub struct StatusArgs {
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,
}

pub fn run(args: StatusArgs) -> Result<()> {
    let db_path = args.db.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".rieko").join("rieko.db")
    });
    let mut storage = SqliteStorage::open(&db_path)
        .with_context(|| format!("opening db {}", db_path.display()))?;

    let schema = storage.schema_version()?;
    let integrity_ok = storage.integrity_check().is_ok();
    let counts = storage.counts()?;
    let operational = storage.read_operational_state()?;

    println!("Rieko status (db: {})", db_path.display());
    println!(
        "  schema version:  {} (current {CURRENT_SCHEMA_VERSION})",
        schema
    );
    // Deterministically confirm the database is intact; refuse to claim it's
    // healthy if integrity checks fail (D9, invariant #8).
    match integrity_ok {
        true => println!("  integrity:      ok"),
        false => {
            println!("  integrity:      FAILED");
            anyhow::bail!("refusing to report healthy: integrity check failed");
        }
    }
    println!("  findings:        {}", counts.findings);
    println!("  recommendations: {}", counts.recommendations);
    println!("  simulations:     {}", counts.simulations);
    println!("  audit entries:   {}", counts.audit);
    println!("  channel snapshots: {}", counts.channel_snapshots);

    match operational.as_ref() {
        Some(state) => {
            let overall = assess(state, &HealthPolicy::default(), Utc::now(), integrity_ok);
            println!("  overall:         {}", overall.as_str());
            println!("  source:          {}", source_label(state));
            println!(
                "  last ingestion:  attempt {} / success {}",
                ts(state.last_ingestion_attempt),
                ts(state.last_ingestion_success)
            );
            println!(
                "  last cycle:      attempt {} / success {}",
                ts(state.last_cycle_attempt),
                ts(state.last_cycle_success)
            );
            println!(
                "  last persist:    success {}",
                ts(state.last_persist_success)
            );
            println!("  llm:             {}", state.llm.as_str());
            println!("  alert sink:      {}", state.alert_sink.as_str());
        }
        None => {
            let overall = assess(
                &OperationalState::default(),
                &HealthPolicy::default(),
                Utc::now(),
                integrity_ok,
            );
            println!("  overall:         {}", overall.as_str());
            println!("  source:          (never ingested)");
        }
    }

    if let Some(last) = storage.recent_audit(1)?.first() {
        info!(last_audit = %last.timestamp.to_rfc3339(), "latest audit entry");
    }
    Ok(())
}

fn ts(t: Option<DateTime<Utc>>) -> String {
    match t {
        Some(t) => t.to_rfc3339(),
        None => "never".to_string(),
    }
}

fn source_label(state: &OperationalState) -> String {
    match state.source {
        rieko_status::SourceState::Fixture => "fixture".to_string(),
        rieko_status::SourceState::LndRest { connected } => {
            format!(
                "lnd-rest ({})",
                if connected {
                    "connected"
                } else {
                    "disconnected"
                }
            )
        }
    }
}
