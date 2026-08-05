use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rieko_alerts::{Alert, AlertSink, DedupingSink, TelegramSink};
use rieko_detectors::{Detector, DetectorContext, DriftDetector, LiquidityDetector};
use rieko_findings::{Finding, Severity};
use rieko_graph::{GraphView, InMemoryHistory};
use rieko_llm::{LlmClient, NullClient, OpenAiCompatibleClient};
use rieko_storage::{SqliteStorage, Storage};
use tracing::{info, warn};

use super::common::{persist_and_recommend, GraphSource};

#[derive(Args, Debug)]
pub struct MonitorArgs {
    /// Path to a JSON fixture matching the LND `/v1/channels` response.
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

    /// Seconds between cycles.
    #[arg(long, default_value_t = 60)]
    interval: u64,

    /// Stop after this many cycles. 0 runs forever (default).
    #[arg(long, default_value_t = 0)]
    cycles: u64,

    /// Cooldown between identical alerts, in seconds.
    #[arg(long, default_value_t = 3600)]
    alert_cooldown: u64,
}

pub fn run(args: MonitorArgs) -> Result<()> {
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

    let llm: Box<dyn LlmClient> = OpenAiCompatibleClient::from_env()
        .map(|c| Box::new(c) as Box<dyn LlmClient>)
        .unwrap_or_else(|| Box::new(NullClient));
    let engine = rieko_recommendations::RecommendationEngine;

    let mut alert_sink = if TelegramSink::is_configured() {
        match TelegramSink::from_env() {
            Ok(sink) => Some(DedupingSink::new(
                sink,
                Duration::from_secs(args.alert_cooldown),
            )),
            Err(e) => {
                warn!("telegram configured but unusable: {e}");
                None
            }
        }
    } else {
        None
    };

    // History lives across cycles so the drift detector can reason over time.
    let mut history = InMemoryHistory::new(200);
    // Last seen finding per dedup key; alerts fire only on new or escalated.
    let mut previous: HashMap<String, Severity> = HashMap::new();

    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(LiquidityDetector::new(args.node.clone())),
        Box::new(DriftDetector::new(args.node.clone())),
    ];

    let mut cycle: u64 = 0;
    loop {
        cycle += 1;

        let graph = source.build()?;
        let (n_nodes, n_channels) = graph.len();

        // Record this cycle's channel states, both in-memory (for detectors)
        // and durably (for the API and future trend queries).
        let now = chrono::Utc::now();
        let channels = graph.channels();
        for channel in &channels {
            history.push(rieko_domain::ChannelSnapshot::from_channel(channel, now));
            storage
                .save_channel_snapshot(&rieko_domain::ChannelSnapshot::from_channel(channel, now))
                .with_context(|| format!("persisting snapshot for {}", channel.id))?;
        }

        let ctx = DetectorContext {
            history: Some(&history),
        };
        let mut findings: Vec<Finding> = Vec::new();
        for detector in &detectors {
            findings.extend(detector.run(&graph, &ctx));
        }
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

        let recommendations =
            persist_and_recommend(&mut storage, &*llm, &engine, &args.node, &findings)?;

        // Transition-aware alerts: new finding or severity escalation only.
        let mut n_alerts = 0u64;
        let mut next_previous: HashMap<String, Severity> = HashMap::new();
        if let Some(sink) = alert_sink.as_mut() {
            for finding in &findings {
                let key = finding.dedup_key();
                let prev = previous.get(&key).copied();
                let should_alert = prev.map_or(true, |p| finding.severity > p);
                if should_alert {
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
                next_previous.insert(key, finding.severity);
            }
        } else {
            for finding in &findings {
                next_previous.insert(finding.dedup_key(), finding.severity);
            }
        }
        previous = next_previous;

        info!(
            cycle,
            n_nodes,
            n_channels,
            findings = findings.len(),
            recommendations = recommendations.len(),
            alerts = n_alerts,
            "cycle complete"
        );

        if args.cycles > 0 && cycle >= args.cycles {
            break;
        }
        std::thread::sleep(Duration::from_secs(args.interval));
    }

    Ok(())
}

fn summarize_finding(finding: &Finding) -> String {
    let parts: Vec<String> = finding
        .evidence
        .iter()
        .map(|e| format!("{}={}", e.key, e.value))
        .collect();
    format!("{:?} severity: {}", finding.severity, parts.join(", "))
}

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(home).join(".rieko");
    std::fs::create_dir_all(&dir).ok();
    dir.join("rieko.db")
}
