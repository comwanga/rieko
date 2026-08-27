use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use rieko_api::routes::{BitcoinInspection, BtcPayInspection, LightningInspection};
use serde::{Deserialize, Serialize};

use super::findings::{ApiArgs, ApiClient};

#[derive(Args, Debug)]
pub struct InspectArgs {
    #[command(subcommand)]
    command: InspectCommand,
}

#[derive(Subcommand, Debug)]
enum InspectCommand {
    /// Show all latest normalized operational states.
    All(AllArgs),
    /// Show the latest normalized Bitcoin Core operational state.
    Bitcoin(BitcoinArgs),
    /// Show the latest normalized BTCPay operational state.
    Btcpay(BtcPayArgs),
    /// Show the latest normalized Lightning operational state.
    Lightning(LightningArgs),
}

#[derive(Args, Debug)]
struct AllArgs {
    #[command(flatten)]
    api: ApiArgs,

    /// Emit the typed API responses as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AllInspection {
    pub(super) btcpay: BtcPayInspection,
    pub(super) bitcoin: BitcoinInspection,
    pub(super) lightning: LightningInspection,
}

#[derive(Args, Debug)]
struct BitcoinArgs {
    #[command(flatten)]
    api: ApiArgs,

    /// Emit the typed API response as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct BtcPayArgs {
    #[command(flatten)]
    api: ApiArgs,

    /// Emit the typed API response as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct LightningArgs {
    #[command(flatten)]
    api: ApiArgs,

    /// Emit the typed API response as JSON.
    #[arg(long)]
    json: bool,
}

pub fn run(args: InspectArgs) -> Result<()> {
    match args.command {
        InspectCommand::All(args) => run_all(args),
        InspectCommand::Bitcoin(args) => run_bitcoin(args),
        InspectCommand::Btcpay(args) => run_btcpay(args),
        InspectCommand::Lightning(args) => run_lightning(args),
    }
}

fn run_all(args: AllArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building combined inspection client runtime")?;
    let client = ApiClient::new(&args.api)?;
    let inspection = runtime.block_on(fetch_all(&client))?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspection)
                .context("rendering typed combined inspection")?
        );
    } else {
        print!("{}", render_all(&inspection, &args.api.api_url));
    }
    Ok(())
}

pub(super) async fn fetch_all(client: &ApiClient) -> Result<AllInspection> {
    // Keep the fan-out deterministic and bounded: at most three existing
    // timeout-bounded requests, in a fixed order, stopping at the first error.
    let btcpay = client.fetch_btcpay_inspection().await?;
    let bitcoin = client.fetch_bitcoin_inspection().await?;
    let lightning = client.fetch_lightning_inspection().await?;
    Ok(AllInspection {
        btcpay,
        bitcoin,
        lightning,
    })
}

fn render_all(inspection: &AllInspection, api_url: &str) -> String {
    [
        render_btcpay(&inspection.btcpay, api_url),
        render_bitcoin(&inspection.bitcoin, api_url),
        render_lightning(&inspection.lightning, api_url),
    ]
    .into_iter()
    .map(|section| section.trim_end().to_owned())
    .collect::<Vec<_>>()
    .join("\n\n")
        + "\n"
}

fn run_bitcoin(args: BitcoinArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building Bitcoin inspection client runtime")?;
    let client = ApiClient::new(&args.api)?;
    let inspection = runtime.block_on(client.fetch_bitcoin_inspection())?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspection)
                .context("rendering typed Bitcoin inspection")?
        );
    } else {
        print!("{}", render_bitcoin(&inspection, &args.api.api_url));
    }
    Ok(())
}

fn render_bitcoin(inspection: &BitcoinInspection, api_url: &str) -> String {
    let mut lines = vec![format!("Bitcoin Core inspection (api: {api_url})")];
    let Some(state) = inspection.state.as_ref() else {
        lines.push("  state:          not observed".into());
        return lines.join("\n") + "\n";
    };

    lines.push(format!(
        "  connectivity:   {}",
        if state.connected {
            "connected"
        } else {
            "disconnected"
        }
    ));
    lines.push(format!("  last attempt:   {}", state.last_attempt));
    lines.push(format!(
        "  last success:   {}",
        state
            .last_success
            .map(|timestamp| timestamp.to_string())
            .unwrap_or_else(|| "never".into())
    ));

    match state.snapshot.as_ref() {
        Some(snapshot) => {
            lines.push(format!("  network:        {}", snapshot.network));
            lines.push(format!("  block height:   {}", snapshot.block_height));
            lines.push(format!("  header height:  {}", snapshot.header_height));
            lines.push(format!("  synchronized:   {}", snapshot.synchronized));
            lines.push(format!("  observed at:    {}", snapshot.observed_at));
        }
        None => lines.push("  snapshot:       not available".into()),
    }
    lines.join("\n") + "\n"
}

fn run_btcpay(args: BtcPayArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building BTCPay inspection client runtime")?;
    let client = ApiClient::new(&args.api)?;
    let inspection = runtime.block_on(client.fetch_btcpay_inspection())?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspection)
                .context("rendering typed BTCPay inspection")?
        );
    } else {
        print!("{}", render_btcpay(&inspection, &args.api.api_url));
    }
    Ok(())
}

fn render_btcpay(inspection: &BtcPayInspection, api_url: &str) -> String {
    let mut lines = vec![format!("BTCPay inspection (api: {api_url})")];
    let Some(state) = inspection.state.as_ref() else {
        lines.push("  state:              not observed".into());
        return lines.join("\n") + "\n";
    };

    lines.push(format!(
        "  connectivity:       {}",
        if state.source.connected() {
            "connected"
        } else {
            "disconnected"
        }
    ));
    lines.push(format!("  observation source: {}", state.source.as_str()));
    lines.push(format!(
        "  last attempt:       {}",
        state
            .last_attempt
            .map(|timestamp| timestamp.to_string())
            .unwrap_or_else(|| "never".into())
    ));
    lines.push(format!(
        "  last success:       {}",
        state
            .last_success
            .map(|timestamp| timestamp.to_string())
            .unwrap_or_else(|| "never".into())
    ));
    lines.push(format!(
        "  source data at:     {}",
        state
            .source_data_at
            .map(|timestamp| timestamp.to_string())
            .unwrap_or_else(|| "never".into())
    ));
    lines.join("\n") + "\n"
}

fn run_lightning(args: LightningArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building Lightning inspection client runtime")?;
    let client = ApiClient::new(&args.api)?;
    let inspection = runtime.block_on(client.fetch_lightning_inspection())?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspection)
                .context("rendering typed Lightning inspection")?
        );
    } else {
        print!("{}", render_lightning(&inspection, &args.api.api_url));
    }
    Ok(())
}

fn render_lightning(inspection: &LightningInspection, api_url: &str) -> String {
    let mut lines = vec![format!("Lightning inspection (api: {api_url})")];
    let Some(state) = inspection.state.as_ref() else {
        lines.push("  state:             not observed".into());
        return lines.join("\n") + "\n";
    };

    lines.push(format!(
        "  connectivity:      {}",
        if state.connected {
            "connected"
        } else {
            "disconnected"
        }
    ));
    lines.push(format!("  last attempt:      {}", state.last_attempt));
    lines.push(format!(
        "  last success:      {}",
        state
            .last_success
            .map(|timestamp| timestamp.to_string())
            .unwrap_or_else(|| "never".into())
    ));

    match state.snapshot.as_ref() {
        Some(snapshot) => {
            lines.push(format!("  node identity:     {}", snapshot.node_id));
            lines.push(format!("  synced to chain:   {}", snapshot.synced_to_chain));
            lines.push(format!("  active channels:   {}", snapshot.active_channels));
            lines.push(format!(
                "  inactive channels: {}",
                snapshot.inactive_channels
            ));
            lines.push(format!("  observed at:       {}", snapshot.observed_at));
        }
        None => lines.push("  snapshot:          not available".into()),
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::get;
    use chrono::{TimeZone, Utc};
    use rieko_domain::{BitcoinCoreSnapshot, BitcoinNetwork, LightningSnapshot};
    use rieko_status::{
        BitcoinCoreState, LightningState, OperationalState, OperationalStateStore, SourceState,
    };
    use rieko_storage::MemoryStorage;

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

    fn observed_state() -> LightningState {
        let observed_at = Utc.with_ymd_and_hms(2026, 8, 27, 10, 0, 0).unwrap();
        LightningState {
            connected: true,
            last_attempt: observed_at,
            last_success: Some(observed_at),
            snapshot: Some(LightningSnapshot {
                node_id: "02abc".into(),
                synced_to_chain: false,
                active_channels: 3,
                inactive_channels: 1,
                observed_at,
            }),
        }
    }

    fn observed_bitcoin_state() -> BitcoinCoreState {
        let observed_at = Utc.with_ymd_and_hms(2026, 8, 27, 10, 0, 0).unwrap();
        BitcoinCoreState {
            connected: true,
            last_attempt: observed_at,
            last_success: Some(observed_at),
            snapshot: Some(BitcoinCoreSnapshot {
                network: BitcoinNetwork::Regtest,
                block_height: 210,
                header_height: 211,
                synchronized: false,
                observed_at,
            }),
        }
    }

    #[tokio::test]
    async fn all_retrieves_groups_and_preserves_three_typed_states_without_a_database() {
        let observed_at = Utc.with_ymd_and_hms(2026, 8, 27, 10, 0, 0).unwrap();
        let bitcoin = observed_bitcoin_state();
        let lightning = observed_state();
        let mut storage = MemoryStorage::new();
        storage
            .write_operational_state(&OperationalState {
                source: SourceState::BtcPayGreenfield { connected: true },
                last_ingestion_attempt: Some(observed_at),
                last_ingestion_success: Some(observed_at),
                source_data_at: Some(observed_at),
                bitcoin_core: Some(bitcoin.clone()),
                lightning: Some(lightning.clone()),
                ..Default::default()
            })
            .unwrap();
        let app = rieko_api::RiekoApi::new(Box::new(storage))
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;

        let inspection = fetch_all(&client(api_url.clone(), None)).await.unwrap();
        let rendered = render_all(&inspection, &api_url);
        let json = serde_json::to_string(&inspection).unwrap();
        let roundtrip: AllInspection = serde_json::from_str(&json).unwrap();

        server.abort();
        assert_eq!(roundtrip, inspection);
        assert_eq!(inspection.bitcoin.state, Some(bitcoin));
        assert_eq!(inspection.lightning.state, Some(lightning));
        assert_eq!(
            inspection.btcpay.state.as_ref().unwrap().source,
            SourceState::BtcPayGreenfield { connected: true }
        );
        assert!(rendered.contains("BTCPay inspection"));
        assert!(rendered.contains("Bitcoin Core inspection"));
        assert!(rendered.contains("Lightning inspection"));
    }

    #[tokio::test]
    async fn all_stops_on_a_partial_non_success_response() {
        let observed_at = Utc.with_ymd_and_hms(2026, 8, 27, 10, 0, 0).unwrap();
        let btcpay = BtcPayInspection {
            state: Some(rieko_api::routes::BtcPayInspectionState {
                source: SourceState::BtcPayGreenfield { connected: true },
                last_attempt: Some(observed_at),
                last_success: Some(observed_at),
                source_data_at: Some(observed_at),
            }),
        };
        let app = axum::Router::new()
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
            );
        let (api_url, server) = start(app).await;

        let error = fetch_all(&client(api_url, None)).await.unwrap_err();

        server.abort();
        assert!(error.to_string().contains("503 Service Unavailable"));
        assert!(error.to_string().contains("Core unavailable"));
    }

    #[tokio::test]
    async fn all_reports_authentication_failure() {
        let app = rieko_api::RiekoApi::new(Box::new(MemoryStorage::new()))
            .unwrap()
            .with_auth("correct-token")
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("token");
        std::fs::write(&token_file, "wrong-token\n").unwrap();

        let error = fetch_all(&client(api_url, Some(token_file)))
            .await
            .unwrap_err();

        server.abort();
        assert!(error.to_string().contains("401 Unauthorized"));
    }

    #[tokio::test]
    async fn retrieves_and_renders_typed_bitcoin_state_without_a_database() {
        let expected = observed_bitcoin_state();
        let mut storage = MemoryStorage::new();
        storage
            .write_operational_state(&OperationalState {
                bitcoin_core: Some(expected.clone()),
                ..Default::default()
            })
            .unwrap();
        let app = rieko_api::RiekoApi::new(Box::new(storage))
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;

        let inspection = client(api_url.clone(), None)
            .fetch_bitcoin_inspection()
            .await
            .unwrap();
        let rendered = render_bitcoin(&inspection, &api_url);

        server.abort();
        assert_eq!(inspection.state, Some(expected));
        assert!(rendered.contains("connectivity:   connected"));
        assert!(rendered.contains("network:        regtest"));
        assert!(rendered.contains("block height:   210"));
        assert!(rendered.contains("header height:  211"));
        assert!(rendered.contains("synchronized:   false"));
        assert!(rendered.contains("last attempt:"));
        assert!(rendered.contains("last success:"));
    }

    #[tokio::test]
    async fn bitcoin_inspection_reports_authentication_failure() {
        let app = rieko_api::RiekoApi::new(Box::new(MemoryStorage::new()))
            .unwrap()
            .with_auth("correct-token")
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("token");
        std::fs::write(&token_file, "wrong-token\n").unwrap();

        let error = client(api_url, Some(token_file))
            .fetch_bitcoin_inspection()
            .await
            .unwrap_err();

        server.abort();
        assert!(error.to_string().contains("401 Unauthorized"));
    }

    #[tokio::test]
    async fn bitcoin_inspection_reports_non_success_and_malformed_responses() {
        let unavailable = axum::Router::new().route(
            "/inspect/bitcoin",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "agent unavailable") }),
        );
        let (api_url, server) = start(unavailable).await;
        let error = client(api_url, None)
            .fetch_bitcoin_inspection()
            .await
            .unwrap_err();
        server.abort();
        assert!(error.to_string().contains("503 Service Unavailable"));

        let malformed =
            axum::Router::new().route("/inspect/bitcoin", get(|| async { "not inspection json" }));
        let (api_url, server) = start(malformed).await;
        let error = client(api_url, None)
            .fetch_bitcoin_inspection()
            .await
            .unwrap_err();
        server.abort();
        assert!(error
            .to_string()
            .contains("decoding typed Bitcoin inspection response"));
    }

    #[tokio::test]
    async fn retrieves_and_renders_typed_btcpay_state_without_a_database() {
        let observed_at = Utc.with_ymd_and_hms(2026, 8, 27, 10, 0, 0).unwrap();
        let mut storage = MemoryStorage::new();
        storage
            .write_operational_state(&OperationalState {
                source: SourceState::BtcPayGreenfield { connected: true },
                last_ingestion_attempt: Some(observed_at),
                last_ingestion_success: Some(observed_at),
                source_data_at: Some(observed_at),
                ..Default::default()
            })
            .unwrap();
        let app = rieko_api::RiekoApi::new(Box::new(storage))
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;

        let inspection = client(api_url.clone(), None)
            .fetch_btcpay_inspection()
            .await
            .unwrap();
        let rendered = render_btcpay(&inspection, &api_url);

        server.abort();
        let state = inspection.state.unwrap();
        assert_eq!(
            state.source,
            SourceState::BtcPayGreenfield { connected: true }
        );
        assert_eq!(state.last_attempt, Some(observed_at));
        assert_eq!(state.last_success, Some(observed_at));
        assert_eq!(state.source_data_at, Some(observed_at));
        assert!(rendered.contains("connectivity:       connected"));
        assert!(rendered.contains("observation source: btcpay_greenfield"));
        assert!(rendered.contains("last attempt:"));
        assert!(rendered.contains("last success:"));
        assert!(rendered.contains("source data at:"));
    }

    #[tokio::test]
    async fn btcpay_inspection_reports_authentication_failure() {
        let app = rieko_api::RiekoApi::new(Box::new(MemoryStorage::new()))
            .unwrap()
            .with_auth("correct-token")
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("token");
        std::fs::write(&token_file, "wrong-token\n").unwrap();

        let error = client(api_url, Some(token_file))
            .fetch_btcpay_inspection()
            .await
            .unwrap_err();

        server.abort();
        assert!(error.to_string().contains("401 Unauthorized"));
    }

    #[tokio::test]
    async fn btcpay_inspection_reports_non_success_and_malformed_responses() {
        let unavailable = axum::Router::new().route(
            "/inspect/btcpay",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "agent unavailable") }),
        );
        let (api_url, server) = start(unavailable).await;
        let error = client(api_url, None)
            .fetch_btcpay_inspection()
            .await
            .unwrap_err();
        server.abort();
        assert!(error.to_string().contains("503 Service Unavailable"));

        let malformed =
            axum::Router::new().route("/inspect/btcpay", get(|| async { "not inspection json" }));
        let (api_url, server) = start(malformed).await;
        let error = client(api_url, None)
            .fetch_btcpay_inspection()
            .await
            .unwrap_err();
        server.abort();
        assert!(error
            .to_string()
            .contains("decoding typed BTCPay inspection response"));
    }

    #[tokio::test]
    async fn retrieves_and_renders_typed_lightning_state_without_a_database() {
        let expected = observed_state();
        let mut storage = MemoryStorage::new();
        storage
            .write_operational_state(&OperationalState {
                lightning: Some(expected.clone()),
                ..Default::default()
            })
            .unwrap();
        let app = rieko_api::RiekoApi::new(Box::new(storage))
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;

        let inspection = client(api_url.clone(), None)
            .fetch_lightning_inspection()
            .await
            .unwrap();
        let rendered = render_lightning(&inspection, &api_url);

        server.abort();
        assert_eq!(inspection.state, Some(expected));
        assert!(rendered.contains("connectivity:      connected"));
        assert!(rendered.contains("node identity:     02abc"));
        assert!(rendered.contains("synced to chain:   false"));
        assert!(rendered.contains("active channels:   3"));
        assert!(rendered.contains("inactive channels: 1"));
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

        let error = client(api_url, Some(token_file))
            .fetch_lightning_inspection()
            .await
            .unwrap_err();

        server.abort();
        assert!(error.to_string().contains("401 Unauthorized"));
    }

    #[tokio::test]
    async fn reports_non_success_and_malformed_responses() {
        let unavailable = axum::Router::new().route(
            "/inspect/lightning",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "agent unavailable") }),
        );
        let (api_url, server) = start(unavailable).await;
        let error = client(api_url, None)
            .fetch_lightning_inspection()
            .await
            .unwrap_err();
        server.abort();
        assert!(error.to_string().contains("503 Service Unavailable"));

        let malformed = axum::Router::new().route(
            "/inspect/lightning",
            get(|| async { "not inspection json" }),
        );
        let (api_url, server) = start(malformed).await;
        let error = client(api_url, None)
            .fetch_lightning_inspection()
            .await
            .unwrap_err();
        server.abort();
        assert!(error
            .to_string()
            .contains("decoding typed Lightning inspection response"));
    }
}
