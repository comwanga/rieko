use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rieko_alerts::{Alert, AlertSink, DedupingSink, TelegramSink};
use rieko_domain::BitcoinNetwork;
use rieko_llm::{LlmClient, OpenAiCompatibleClient};
use rieko_storage::SqliteStorage;
use tracing::info;
use tracing::warn;

use super::common::{persist_and_recommend, GraphSource};

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Bitcoin network observed by this source.
    #[arg(long, value_name = "NETWORK")]
    network: BitcoinNetwork,

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
        network: args.network,
        fixture: args.fixture.clone(),
        lnd_rest: args.lnd_rest.clone(),
        macaroon: args.macaroon.clone(),
        tls_cert: args.tls_cert.clone(),
        node: args.node.clone(),
    };
    super::common::record_ingestion_attempt(&mut storage, &source)?;
    let graph = match source.build() {
        Ok(graph) => graph,
        Err(error) => {
            super::common::record_ingestion_failure(&mut storage, &source)
                .with_context(|| format!("recording ingestion failure after: {error:#}"))?;
            return Err(error);
        }
    };
    super::common::record_ingestion_success(
        &mut storage,
        &source,
        super::common::newest_source_data_at(&graph),
    )?;
    let (n_nodes, n_channels) = graph.len();
    info!(n_nodes, n_channels, "graph loaded");

    super::common::record_cycle_attempt(&mut storage)?;
    let observation_source = source.observation_source()?;
    let normalizer = source.normalizer();
    let detector_context = rieko_detectors::DetectorContext {
        network: source.network,
        history: None,
        source: Some(&observation_source),
        normalizer: Some(&normalizer),
        node: Some(&args.node),
    };
    let detectors: Vec<Box<dyn rieko_detectors::Detector>> = vec![
        Box::new(rieko_detectors::LiquidityDetector::new(args.node.clone())),
        Box::new(rieko_detectors::DriftDetector::new(args.node.clone())),
    ];
    let mut cycles = Vec::new();
    for detector in &detectors {
        cycles.push(detector.evaluate(&graph, &detector_context)?);
    }
    let scopes: Vec<_> = cycles.iter().map(|cycle| cycle.scope.clone()).collect();
    let mut findings: Vec<_> = cycles
        .into_iter()
        .flat_map(|cycle| cycle.findings)
        .collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

    let llm = OpenAiCompatibleClient::from_env().context("building LLM client")?;
    super::common::record_component(
        &mut storage,
        super::common::ComponentKind::Llm,
        if llm.is_some() {
            rieko_status::ComponentState::Configured
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

    let recommendations = persist_and_recommend(
        &mut storage,
        llm.as_ref().map(|client| client as &dyn LlmClient),
        &engine,
        &args.node,
        &scopes,
        &mut findings,
    )?;

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
                Ok(()) => {
                    n_alerts += 1;
                    super::common::record_component(
                        &mut storage,
                        super::common::ComponentKind::AlertSink,
                        rieko_status::ComponentState::Healthy,
                    )?;
                }
                Err(e) => {
                    // A delivery failure must surface in operational status
                    // (RIEKO-AUDIT-013) while findings stay persisted.
                    warn!(error = %e, "alert delivery failed");
                    super::common::record_component(
                        &mut storage,
                        super::common::ComponentKind::AlertSink,
                        rieko_status::ComponentState::Failing,
                    )?;
                }
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
