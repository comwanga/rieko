use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rieko_alerts::{Alert, AlertSink, AlertStateStore, PersistentDedupingSink, TelegramSink};
use rieko_detectors::{Detector, DetectorContext, DriftDetector, LiquidityDetector};
use rieko_findings::Finding;
use rieko_graph::{GraphView, InMemoryHistory};
use rieko_llm::{LlmClient, NullClient, OpenAiCompatibleClient};
use rieko_status::OperationalStateStore;
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

    /// Snapshot retention period in days (RIEKO-AUDIT-016). Default: 30.
    #[arg(long, default_value_t = 30, value_name = "DAYS")]
    retention_days: u64,

    /// Retention period in days for closed channels. Default: 3.
    #[arg(long, default_value_t = 3, value_name = "DAYS")]
    closed_retention_days: u64,

    /// Optional cap on snapshots kept per channel (newest wins). Unset keeps
    /// time-based retention only.
    #[arg(long, value_name = "ROWS")]
    max_snapshots_per_channel: Option<usize>,

    /// How often a cleanup pass runs, in hours. Default: 6.
    #[arg(long, default_value_t = 6, value_name = "HOURS")]
    cleanup_interval: u64,
}

pub fn run(args: MonitorArgs) -> Result<()> {
    let db_path = args.db.clone().unwrap_or_else(default_db_path);
    let mut storage = SqliteStorage::open(&db_path)
        .with_context(|| format!("opening db {}", db_path.display()))?;

    // Guard against two monitors writing the same database. A second writer is
    // rejected up front rather than silently racing (D9, invariant #8).
    let _writer = storage
        .writer_lock(&db_path)
        .with_context(|| format!("locking db {}", db_path.display()))?;

    let source = GraphSource {
        fixture: args.fixture.clone(),
        lnd_rest: args.lnd_rest.clone(),
        macaroon: args.macaroon.clone(),
        tls_cert: args.tls_cert.clone(),
        node: args.node.clone(),
    };

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
                // Dedup state lives in a separate connection to the same DB,
                // shared (WAL) with the main one. This keeps the sink's store
                // out of the `&mut storage` borrow in the loop while still
                // surviving a restart.
                let store: Box<dyn AlertStateStore> =
                    Box::new(SqliteStorage::open(&db_path).with_context(|| {
                        format!("opening alert-state db {}", db_path.display())
                    })?);
                super::common::record_component(
                    &mut storage,
                    super::common::ComponentKind::AlertSink,
                    rieko_status::ComponentState::Healthy,
                )?;
                Some(PersistentDedupingSink::new(
                    sink,
                    store,
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

    // History lives across cycles so the drift detector can reason over time.
    let mut history = InMemoryHistory::new(200);

    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(LiquidityDetector::new(args.node.clone())),
        Box::new(DriftDetector::new(args.node.clone())),
    ];

    // Retention is operator-overridable and defaults to a documented upper
    // bound (RIEKO-AUDIT-016).
    let retention = rieko_storage::RetentionPolicy {
        snapshot_max_age: std::time::Duration::from_secs(args.retention_days * 24 * 3600),
        closed_channel_max_age: std::time::Duration::from_secs(
            args.closed_retention_days * 24 * 3600,
        ),
        max_snapshots_per_channel: args.max_snapshots_per_channel,
        max_total_snapshots: None,
        cleanup_interval: std::time::Duration::from_secs(args.cleanup_interval * 3600),
    };

    let mut cycle: u64 = 0;
    let mut last_cleanup: Option<chrono::DateTime<chrono::Utc>> = None;
    loop {
        cycle += 1;

        let graph = source.build()?;
        let (n_nodes, n_channels) = graph.len();

        // Ingestion reached this point, so the source is reachable and current.
        super::common::record_source_ingestion(&mut storage, &source)?;

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

        // Retention: bounded cleanup at most once per cleanup_interval
        // (RIEKO-AUDIT-016). Cleanup only touches channel_snapshots and is
        // transactional; the outcome is recorded so /status reports failures.
        if last_cleanup.map_or(true, |t| {
            chrono::Utc::now() - t
                >= chrono::Duration::from_std(retention.cleanup_interval)
                    .unwrap_or(chrono::Duration::zero())
        }) {
            let now = chrono::Utc::now();
            let mut op = storage
                .read_operational_state()
                .unwrap_or_default()
                .unwrap_or_default();
            op.last_cleanup_attempt = Some(now);
            match storage.prune_channel_snapshots(&retention, now) {
                Ok(summary) => {
                    op.cleanup = rieko_status::ComponentState::Healthy;
                    op.last_cleanup_success = Some(now);
                    info!(
                        deleted_snapshots = summary.deleted_snapshots,
                        "retention cleanup complete"
                    );
                    last_cleanup = Some(now);
                }
                Err(e) => {
                    op.cleanup = rieko_status::ComponentState::Failing;
                    warn!(error = %e, "retention cleanup failed");
                }
            }
            storage
                .write_operational_state(&op)
                .context("recording cleanup state")?;
        }

        // Cooldown and severity-escalation are enforced by the persistent
        // sink, so the loop only decides *what* to say, not *whether*.
        let mut n_alerts = 0u64;
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
