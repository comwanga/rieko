use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
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

    let findings = storage.latest_findings(1_000_000)?;
    let recommendations = storage.latest_recommendations(1_000_000)?;
    let audit = storage.recent_audit(1_000_000)?;
    let simulations = storage.recent_simulations(1_000_000)?;

    let critical = findings
        .iter()
        .filter(|f| f.severity == rieko_findings::Severity::Critical)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == rieko_findings::Severity::Warning)
        .count();

    let stage_counts = |stage: rieko_findings::ActionStage| {
        recommendations
            .iter()
            .filter(|r| r.action.stage == stage)
            .count()
    };

    println!("Rieko status (db: {})", db_path.display());
    println!(
        "  schema version:  {} (current {CURRENT_SCHEMA_VERSION})",
        storage.schema_version()?
    );
    println!("  findings:        {}", findings.len());
    println!("    critical:      {critical}");
    println!("    warning:       {warnings}");
    println!("  recommendations: {}", recommendations.len());
    println!(
        "    recommended:   {}",
        stage_counts(rieko_findings::ActionStage::Recommended)
    );
    println!(
        "    simulated:     {}",
        stage_counts(rieko_findings::ActionStage::Simulated)
    );
    println!(
        "    approved:      {}",
        stage_counts(rieko_findings::ActionStage::Approved)
    );
    println!(
        "    executed:      {}",
        stage_counts(rieko_findings::ActionStage::Executed)
    );
    println!(
        "    rejected:      {}",
        stage_counts(rieko_findings::ActionStage::Rejected)
    );
    println!(
        "    failed:        {}",
        stage_counts(rieko_findings::ActionStage::Failed)
    );
    println!("  simulations:     {}", simulations.len());
    println!("  audit entries:   {}", audit.len());

    if let Some(last) = audit.first() {
        info!(last_audit = %last.timestamp.to_rfc3339(), "latest audit entry");
    }
    Ok(())
}
