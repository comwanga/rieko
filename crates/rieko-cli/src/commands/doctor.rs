use anyhow::{Context, Result};
use clap::Args;
use rieko_api::routes::Status;
use rieko_findings::Finding;
use serde::{Deserialize, Serialize};

use super::findings::{ApiArgs, ApiClient, Lifecycle};
use super::inspect::{fetch_all, AllInspection};

const ACTIVE_FINDING_LIMIT: u32 = 100;

#[derive(Args, Debug)]
pub struct DoctorArgs {
    #[command(flatten)]
    api: ApiArgs,

    /// Emit the typed diagnostic report as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DoctorReport {
    status: Status,
    inspections: AllInspection,
    active_findings: Vec<Finding>,
}

pub fn run(args: DoctorArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building doctor client runtime")?;
    let client = ApiClient::new(&args.api)?;
    let report = runtime.block_on(fetch_report(&client))?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("rendering typed doctor report")?
        );
    } else {
        print!("{}", render_report(&report, &args.api.api_url));
    }
    Ok(())
}

async fn fetch_report(client: &ApiClient) -> Result<DoctorReport> {
    // Five requests at most, each protected by the shared client timeout. A
    // fixed order makes partial failures deterministic and avoids unbounded fan-out.
    let status = client.fetch_status().await?;
    let inspections = fetch_all(client).await?;
    let active_findings = client
        .fetch_findings(ACTIVE_FINDING_LIMIT, Lifecycle::Active)
        .await?;
    Ok(DoctorReport {
        status,
        inspections,
        active_findings,
    })
}

fn render_report(report: &DoctorReport, api_url: &str) -> String {
    let mut lines = vec![
        format!("Rieko doctor (api: {api_url})"),
        format!("  overall:          {}", report.status.overall),
        format!("  integrity:        {}", report.status.integrity),
        format!(
            "  BTCPay:           {}",
            btcpay_summary(&report.inspections)
        ),
        format!(
            "  Bitcoin Core:     {}",
            bitcoin_summary(&report.inspections)
        ),
        format!(
            "  Lightning:        {}",
            lightning_summary(&report.inspections)
        ),
        format!("  active findings:  {}", report.active_findings.len()),
    ];
    for finding in &report.active_findings {
        lines.push(format!(
            "    - {} [{:?}] lifecycle={:?} id={} last_seen={}",
            finding.detector, finding.severity, finding.lifecycle, finding.id, finding.last_seen_at
        ));
    }
    lines.join("\n") + "\n"
}

fn btcpay_summary(inspections: &AllInspection) -> String {
    let Some(state) = inspections.btcpay.state.as_ref() else {
        return "not observed".into();
    };
    format!(
        "{}; source={}; last_attempt={}; last_success={}",
        connected_label(state.source.connected()),
        state.source.as_str(),
        optional_timestamp(state.last_attempt),
        optional_timestamp(state.last_success)
    )
}

fn bitcoin_summary(inspections: &AllInspection) -> String {
    let Some(state) = inspections.bitcoin.state.as_ref() else {
        return "not observed".into();
    };
    let snapshot = state.snapshot.as_ref().map_or_else(
        || "snapshot=not available".into(),
        |snapshot| {
            format!(
                "network={}; blocks={}; headers={}; synchronized={}",
                snapshot.network,
                snapshot.block_height,
                snapshot.header_height,
                snapshot.synchronized
            )
        },
    );
    format!("{}; {snapshot}", connected_label(state.connected))
}

fn lightning_summary(inspections: &AllInspection) -> String {
    let Some(state) = inspections.lightning.state.as_ref() else {
        return "not observed".into();
    };
    let snapshot = state.snapshot.as_ref().map_or_else(
        || "snapshot=not available".into(),
        |snapshot| {
            format!(
                "node={}; synced_to_chain={}; active_channels={}; inactive_channels={}",
                snapshot.node_id,
                snapshot.synced_to_chain,
                snapshot.active_channels,
                snapshot.inactive_channels
            )
        },
    );
    format!("{}; {snapshot}", connected_label(state.connected))
}

fn connected_label(connected: bool) -> &'static str {
    if connected {
        "connected"
    } else {
        "disconnected"
    }
}

fn optional_timestamp(timestamp: Option<chrono::DateTime<chrono::Utc>>) -> String {
    timestamp
        .map(|timestamp| timestamp.to_string())
        .unwrap_or_else(|| "never".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::get;
    use chrono::Utc;
    use rieko_api::routes::{
        BtcPayInspection, BtcPayInspectionState, LightningInspection, StatusCounts,
    };
    use rieko_domain::{BitcoinCoreSnapshot, BitcoinNetwork, LightningSnapshot};
    use rieko_findings::{Evidence, FindingLifecycle, Severity, FINDING_SCHEMA_VERSION};
    use rieko_status::{
        BitcoinCoreState, LightningState, OperationalState, OperationalStateStore, SourceState,
    };
    use rieko_storage::{MemoryStorage, Storage};

    async fn start(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), server)
    }

    fn client(api_url: String, token_file: Option<std::path::PathBuf>) -> ApiClient {
        ApiClient::new(&ApiArgs {
            api_url,
            token_file,
        })
        .unwrap()
    }

    fn healthy_state() -> OperationalState {
        let observed_at = Utc::now();
        OperationalState {
            source: SourceState::BtcPayGreenfield { connected: true },
            last_ingestion_attempt: Some(observed_at),
            last_ingestion_success: Some(observed_at),
            last_cycle_attempt: Some(observed_at),
            last_cycle_success: Some(observed_at),
            last_persist_success: Some(observed_at),
            source_data_at: Some(observed_at),
            bitcoin_core: Some(BitcoinCoreState {
                connected: true,
                last_attempt: observed_at,
                last_success: Some(observed_at),
                snapshot: Some(BitcoinCoreSnapshot {
                    network: BitcoinNetwork::Regtest,
                    block_height: 210,
                    header_height: 210,
                    synchronized: true,
                    observed_at,
                }),
            }),
            lightning: Some(LightningState {
                connected: true,
                last_attempt: observed_at,
                last_success: Some(observed_at),
                snapshot: Some(LightningSnapshot {
                    node_id: "02abc".into(),
                    synced_to_chain: true,
                    active_channels: 2,
                    inactive_channels: 0,
                    observed_at,
                }),
            }),
            ..Default::default()
        }
    }

    fn active_finding() -> Finding {
        let observed_at = Utc::now();
        Finding {
            id: "finding-1".into(),
            detector: "bitcoin_core_sync_correlation".into(),
            detector_version: "1".into(),
            schema_version: FINDING_SCHEMA_VERSION,
            severity: Severity::Warning,
            node: None,
            channel: None,
            evidence: vec![Evidence::text("synchronized", "false")],
            provenance: None,
            explanation: Some("Bitcoin Core is catching up".into()),
            timestamp: observed_at,
            first_seen_at: observed_at,
            last_seen_at: observed_at,
            lifecycle: FindingLifecycle::Active,
        }
    }

    #[tokio::test]
    async fn reports_a_healthy_system_and_preserves_typed_json_without_a_database() {
        let mut storage = MemoryStorage::new();
        storage.write_operational_state(&healthy_state()).unwrap();
        let app = rieko_api::RiekoApi::new(Box::new(storage))
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;

        let report = fetch_report(&client(api_url.clone(), None)).await.unwrap();
        let rendered = render_report(&report, &api_url);
        let json = serde_json::to_string(&report).unwrap();
        let roundtrip: DoctorReport = serde_json::from_str(&json).unwrap();

        server.abort();
        assert_eq!(roundtrip, report);
        assert_eq!(report.status.overall, "healthy");
        assert!(report.active_findings.is_empty());
        assert!(rendered.contains("overall:          healthy"));
        assert!(rendered.contains("BTCPay:           connected"));
        assert!(rendered.contains("Bitcoin Core:     connected"));
        assert!(rendered.contains("Lightning:        connected"));
        assert!(rendered.contains("active findings:  0"));
    }

    #[tokio::test]
    async fn reports_an_active_finding_with_its_existing_lifecycle() {
        let expected = active_finding();
        let mut storage = MemoryStorage::new();
        storage.write_operational_state(&healthy_state()).unwrap();
        storage.save_finding(&expected).unwrap();
        let app = rieko_api::RiekoApi::new(Box::new(storage))
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;

        let report = fetch_report(&client(api_url.clone(), None)).await.unwrap();
        let rendered = render_report(&report, &api_url);

        server.abort();
        assert_eq!(report.active_findings, vec![expected]);
        assert!(rendered.contains("active findings:  1"));
        assert!(rendered.contains("bitcoin_core_sync_correlation"));
        assert!(rendered.contains("lifecycle=Active"));
    }

    #[tokio::test]
    async fn stops_on_a_partial_inspection_api_failure() {
        let observed_at = Utc::now();
        let status = Status {
            engine: "rieko".into(),
            version: "test".into(),
            schema_version: 1,
            read_only: true,
            integrity: "ok".into(),
            overall: "healthy".into(),
            source: Some("btcpay_greenfield (connected)".into()),
            source_data_at: Some(observed_at.to_rfc3339()),
            last_ingestion: None,
            last_cycle: None,
            llm: "not_configured".into(),
            alert_sink: "not_configured".into(),
            cleanup: "not_configured".into(),
            last_cleanup: None,
            counts: StatusCounts {
                findings: 0,
                recommendations: 0,
                simulations: 0,
                audit: 0,
                channel_snapshots: 0,
                simulation_completed: 0,
                simulation_failed: 0,
                simulation_stale: 0,
            },
        };
        let btcpay = BtcPayInspection {
            state: Some(BtcPayInspectionState {
                source: SourceState::BtcPayGreenfield { connected: true },
                last_attempt: Some(observed_at),
                last_success: Some(observed_at),
                source_data_at: Some(observed_at),
            }),
        };
        let app = axum::Router::new()
            .route(
                "/status",
                get(move || {
                    let status = status.clone();
                    async move { axum::Json(status) }
                }),
            )
            .route(
                "/inspect/btcpay",
                get(move || {
                    let btcpay = btcpay.clone();
                    async move { axum::Json(btcpay) }
                }),
            )
            .route(
                "/inspect/bitcoin",
                get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "Core unavailable") }),
            )
            .route(
                "/inspect/lightning",
                get(|| async { axum::Json(LightningInspection { state: None }) }),
            )
            .route(
                "/findings",
                get(|| async { axum::Json(Vec::<Finding>::new()) }),
            );
        let (api_url, server) = start(app).await;

        let error = fetch_report(&client(api_url, None)).await.unwrap_err();

        server.abort();
        assert!(error.to_string().contains("503 Service Unavailable"));
        assert!(error.to_string().contains("Core unavailable"));
    }

    #[tokio::test]
    async fn reports_authentication_failure() {
        let app = rieko_api::RiekoApi::new(Box::new(MemoryStorage::new()))
            .unwrap()
            .with_auth("correct-token")
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("token");
        std::fs::write(&token_file, "wrong-token\n").unwrap();

        let error = fetch_report(&client(api_url, Some(token_file)))
            .await
            .unwrap_err();

        server.abort();
        assert!(error.to_string().contains("401 Unauthorized"));
    }
}
