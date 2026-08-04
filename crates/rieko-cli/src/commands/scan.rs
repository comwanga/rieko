use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use rieko_alerts::{Alert, AlertSink, DedupingSink, TelegramSink};
use rieko_detectors::Detector;
use rieko_domain::NodeId;
use rieko_graph::{GraphStore, InMemoryGraph};
use rieko_ingest_lnd::{LndChannelResponse, LndClient, Normalizer};
use rieko_llm::{ExplainRequest, LlmClient, NullClient, OpenAiCompatibleClient};
use rieko_storage::{SqliteStorage, Storage};
use tracing::{debug, info, warn};

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

    /// Local node id (pubkey). Defaults to `local-node`.
    #[arg(long, default_value = "local-node")]
    node: String,

    /// Durable database path. Defaults to `~/.rieko/rieko.db`.
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,

    /// Cooldown between identical alerts, in seconds.
    #[arg(long, default_value_t = 3600)]
    alert_cooldown: u64,

    /// Emit recommendations even if there are no findings (dry run reporting).
    #[arg(long)]
    verbose: bool,
}

pub fn run(args: ScanArgs) -> Result<()> {
    let db_path = args
        .db
        .clone()
        .unwrap_or_else(default_db_path);
    let mut storage = SqliteStorage::open(&db_path)
        .with_context(|| format!("opening db {}", db_path.display()))?;

    let graph = build_graph(&args)?;
    let (n_nodes, n_channels) = graph.len();
    info!(n_nodes, n_channels, "graph loaded");

    let detector = rieko_detectors::LiquidityDetector::new(NodeId::new(&args.node));
    let findings = detector.run(&graph);
    info!(findings = findings.len(), "detection complete");

    let llm: Box<dyn LlmClient> = OpenAiCompatibleClient::from_env()
        .map(|c| Box::new(c) as Box<dyn LlmClient>)
        .unwrap_or_else(|| Box::new(NullClient));

    let recommendations_engine = rieko_recommendations::RecommendationEngine;

    // Optional alert sink with cooldown (D9). Only constructed if configured.
    let mut alert_sink = if TelegramSink::is_configured() {
        match TelegramSink::from_env() {
            Ok(sink) => Some(DedupingSink::new(sink, Duration::from_secs(args.alert_cooldown))),
            Err(e) => {
                warn!("telegram configured but unusable: {e}");
                None
            }
        }
    } else {
        None
    };

    let mut n_findings = 0;
    let mut n_recommendations = 0;
    let mut n_alerts = 0;

    for finding in &findings {
        storage
            .save_finding(finding)
            .context("persisting finding")?;
        n_findings += 1;

        // LLM explanation (D1): summarizes structured evidence; optional.
        match llm.explain(&ExplainRequest {
            finding,
            context: Some(format!("local node id {}", args.node)),
        }) {
            Ok(Some(text)) => {
                debug!(finding = %finding.id, "llm explanation generated");
                let mut f = finding.clone();
                f.explanation = Some(text);
                storage.save_finding(&f).context("persisting explained finding")?;
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, "llm explanation failed; keeping structured finding"),
        }

        // Recommendations + audit log (D7): every action audited.
        let recs = recommendations_engine
            .recommend(finding)
            .unwrap_or_default();
        for rec in &recs {
            storage.save_recommendation(rec).context("persisting recommendation")?;
            let audit = rieko_findings::AuditEntry::from_action(
                &rec.action,
                "system",
                serde_json::json!({"finding_id": rec.finding_id}),
            );
            storage.append_audit(&audit).context("appending audit")?;
            n_recommendations += 1;
            info!(
                action = rec.action.action_type.as_str(),
                target = rec.action.target.as_deref().unwrap_or(""),
                summary = %rec.action.summary,
                "recommendation"
            );
        }

        // Alert (deduped).
        if let Some(sink) = alert_sink.as_mut() {
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
            findings = n_findings,
            recommendations = n_recommendations,
            alerts = n_alerts,
            "scan complete"
        );
    }

    print_summary(&findings);
    Ok(())
}

fn build_graph(args: &ScanArgs) -> Result<InMemoryGraph> {
    let local = NodeId::new(args.node.clone());
    let mut graph = InMemoryGraph::new();

    let channels = if let Some(fixture) = &args.fixture {
        load_fixture(fixture, &local)?
    } else if let Some(rest) = &args.lnd_rest {
        let macaroon = args
            .macaroon
            .as_ref()
            .map(|p| std::fs::read_to_string(p).map(|s| s.trim().to_string()))
            .transpose()
            .context("reading macaroon")?;
        let client = LndClient::new(rest, macaroon);
        client.channels(&local).context("fetching channels from LND")?
    } else {
        bail!("provide --fixture or --lnd-rest")
    };

    graph
        .upsert_channels(channels)
        .context("loading channels into graph")?;
    Ok(graph)
}

fn load_fixture(path: &Path, local: &NodeId) -> Result<Vec<rieko_domain::Channel>> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading fixture {}", path.display()))?;
    let parsed: LndChannelResponse =
        serde_json::from_str(&body).context("parsing fixture as LND channel response")?;
    let now = chrono::Utc::now();
    parsed
        .channels
        .iter()
        .map(|c| Normalizer::channel(c, local, now).map_err(|e| anyhow!(e.to_string())))
        .collect()
}

fn summarize_finding(finding: &rieko_findings::Finding) -> String {
    let mut parts = Vec::new();
    for e in &finding.evidence {
        parts.push(format!("{}={}", e.key, e.value));
    }
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
        println!("  [{sev}] {} {}", f.detector, f.channel.as_deref().unwrap_or(""));
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
