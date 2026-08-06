use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rieko_alerts::{Alert, AlertSink, DedupingSink, TelegramSink};
use rieko_detectors::Detector;
use rieko_llm::{LlmClient, NullClient, OpenAiCompatibleClient};
use rieko_storage::SqliteStorage;
use tracing::info;
use tracing::warn;

use super::common::{persist_and_recommend, GraphSource};

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Path to a JSON fixture matching the LND `/v1/channels` response.
    /// Mutually exclusive with `--lnd-rest`.
    #[arg(long, value_name = "FILE")]
    fixture: Option<PathBuf>,

    /// LND REST base URL, e.g. `https://localhost:8080`.
    #[arg(long, value_name = "URL", conflicts_with = "fixture")]
    lnd_rest: Option<String>,

    /// Path to a read-only macaroon file for the REST connection.
    #[arg(long, value_name = "FILE")]
    macaroon: Option<PathBuf>,

    /// Path to LND's TLS certificate (tls.cert), trusted for this client only.
    #[arg(long, value_name = "FILE")]
    tls_cert: Option<PathBuf>,

    /// Local node id (pubkey). Defaults to `local-node`.
    #[arg(long, default_value = "local-node")]
    node: String,

    /// Durable database path. Defaults to `~/.rieko/rieko.db`.
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,

    /// Cooldown between identical alerts, in seconds.
    #[arg(long, default_value_t = 3600)]
    alert_cooldown: u64,

    /// Print a summary even when nothing was found.
    #[arg(long)]
    verbose: bool,
}

pub fn run(args: ScanArgs) -> Result<()> {
    let db_path = args.db.clone().unwrap_or_else(default_db_path);
    let mut storage = SqliteStorage::open(&db_path)
        .with_context(|| format!("opening db {}", db_path.display()))?;

    let source = GraphSource {
        fixture: args.fixture.clone(),
        lnd_rest: args.lnd_rest.clone(),
        macaroon: args.macaroon.clone(),
        tls_cert: args.tls_cert.clone(),
        node: args.node.clone(),
    };
    let graph = source.build()?;
    super::common::record_source_ingestion(&mut storage, &source)?;
    let (n_nodes, n_channels) = graph.len();
    info!(n_nodes, n_channels, "graph loaded");

    let detector = rieko_detectors::LiquidityDetector::new(args.node.clone());
    let findings = detector.run(&graph, &rieko_detectors::DetectorContext::no_context());
    info!(findings = findings.len(), "detection complete");

    let (llm, llm_configured): (Box<dyn LlmClient>, bool) = match OpenAiCompatibleClient::from_env()
    {
        Some(c) => (Box::new(c) as Box<dyn LlmClient>, true),
        None => (Box::new(NullClient), false),
    };
    super::common::record_component(
        &mut storage,
        super::common::ComponentKind::Llm,
        if llm_configured {
            rieko_status::ComponentState::Healthy
        } else {
            rieko_status::ComponentState::NotConfigured
        },
    )?;
    let engine = rieko_recommendations::RecommendationEngine;

    let mut alert_sink = if TelegramSink::is_configured() {
        match TelegramSink::from_env() {
            Ok(sink) => {
                super::common::record_component(
                    &mut storage,
                    super::common::ComponentKind::AlertSink,
                    rieko_status::ComponentState::Healthy,
                )?;
                Some(DedupingSink::new(
                    sink,
                    Duration::from_secs(args.alert_cooldown),
                ))
            }
            Err(e) => {
                super::common::record_component(
                    &mut storage,
                    super::common::ComponentKind::AlertSink,
                    rieko_status::ComponentState::Failing,
                )?;
                warn!("telegram configured but unusable: {e}");
                None
            }
        }
    } else {
        super::common::record_component(
            &mut storage,
            super::common::ComponentKind::AlertSink,
            rieko_status::ComponentState::NotConfigured,
        )?;
        None
    };

    let recommendations =
        persist_and_recommend(&mut storage, &*llm, &engine, &args.node, &findings)?;

    let mut n_alerts = 0;
    if let Some(sink) = alert_sink.as_mut() {
        for finding in &findings {
            let alert = Alert::from_finding(
                finding,
                format!(
                    "{}: {}",
                    finding.detector,
                    finding.channel.as_deref().unwrap_or("(node)")
                ),
                finding
                    .explanation
                    .clone()
                    .unwrap_or_else(|| summarize_finding(finding)),
            );
            match sink.send(&alert) {
                Ok(()) => n_alerts += 1,
                Err(e) => warn!(error = %e, "alert delivery failed"),
            }
        }
    }

    if args.verbose || findings.is_empty() {
        info!(
            findings = findings.len(),
            recommendations = recommendations.len(),
            alerts = n_alerts,
            "scan complete"
        );
    }

    print_summary(&findings);
    Ok(())
}

fn summarize_finding(finding: &rieko_findings::Finding) -> String {
    let parts: Vec<String> = finding
        .evidence
        .iter()
        .map(|e| format!("{}={}", e.key, e.value))
        .collect();
    format!("{:?} severity: {}", finding.severity, parts.join(", "))
}

fn print_summary(findings: &[rieko_findings::Finding]) {
    if findings.is_empty() {
        println!("No findings. All observed channels are healthy.");
        return;
    }
    println!("Findings:");
    for f in findings {
        let sev = match f.severity {
            rieko_findings::Severity::Critical => "CRITICAL",
            rieko_findings::Severity::Warning => "warning",
            rieko_findings::Severity::Info => "info",
        };
        println!(
            "  [{sev}] {} {}",
            f.detector,
            f.channel.as_deref().unwrap_or("")
        );
        match &f.explanation {
            Some(e) => println!("      {e}"),
            None => {
                for ev in &f.evidence {
                    println!("      - {}: {}", ev.key, ev.value);
                }
            }
        }
    }
}

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(home).join(".rieko");
    std::fs::create_dir_all(&dir).ok();
    dir.join("rieko.db")
}
