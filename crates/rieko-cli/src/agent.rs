use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use rieko_api::RiekoApi;
use rieko_detectors::{
    BitcoinCoreSyncCorrelationDetector, BtcPayBackendHealthDetector, Detector, DetectorContext,
    LightningChainSyncCorrelationDetector, SettlementReliabilityDetector,
};
use rieko_domain::{BitcoinNetwork, NodeEvent, NodeIngestionAdapter, NodeSnapshot};
use rieko_findings::channel_snapshot_state_digest;
use rieko_graph::InMemoryGraph;
use rieko_ingest_btcpay::{BtcPayAdapter, BtcPayAdapterConfig, BtcPayGreenfieldClient};
use rieko_ingest_core::BitcoinCoreRpcClient;
use rieko_ingest_lnd::{LndAdapter, LndClient};
use rieko_storage::{SqliteStorage, Storage, WebhookEventRecord};
use tokio::sync::{mpsc, watch, Mutex};
use tracing::{info, warn};

const BTCPAY_EVENT_BUFFER: usize = 1024;
const BTCPAY_DETECTOR_WINDOW: usize = 100;
const BTCPAY_CORE_CORRELATION_NODE: &str = "btcpay-greenfield";
const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Startup configuration shared by the `rieko-agent` executable and the
/// backwards-compatible `rieko serve` command.
#[derive(Args, Debug)]
pub struct AgentArgs {
    /// Optional non-secret connection configuration written by `rieko attach`.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,

    #[arg(long, default_value = "127.0.0.1:8080", value_name = "ADDR")]
    addr: SocketAddr,

    /// Directory of built frontend assets to serve at `/`.
    #[arg(long, value_name = "DIR")]
    static_dir: Option<PathBuf>,

    /// Explicitly allow binding to a non-loopback address. External exposure
    /// requires a bearer token via `--token-file` or `RIEKO_API_TOKEN`.
    #[arg(long)]
    allow_external: bool,

    /// File whose first line is the bearer token required for non-loopback
    /// requests. Overrides `RIEKO_API_TOKEN`.
    #[arg(long, value_name = "FILE")]
    token_file: Option<PathBuf>,

    /// Trust proxy-provided client address headers.
    #[arg(long)]
    behind_proxy: bool,

    /// File whose first non-empty line is the BTCPay webhook secret.
    #[arg(
        long,
        value_name = "FILE",
        requires_all = ["btcpay_network", "btcpay_node"]
    )]
    btcpay_webhook_secret_file: Option<PathBuf>,

    /// Bitcoin network associated with BTCPay webhook findings.
    #[arg(long, value_name = "NETWORK", requires = "btcpay_webhook_secret_file")]
    btcpay_network: Option<BitcoinNetwork>,

    /// Local node identity used to scope BTCPay webhook findings.
    #[arg(long, value_name = "NODE", requires = "btcpay_webhook_secret_file")]
    btcpay_node: Option<String>,

    /// BTCPay Server base URL for bounded Greenfield health polling.
    #[arg(
        long,
        value_name = "URL",
        requires_all = [
            "btcpay_greenfield_api_key_file",
            "btcpay_greenfield_store",
            "btcpay_greenfield_network"
        ]
    )]
    btcpay_greenfield_url: Option<String>,

    /// File containing a scoped, read-only BTCPay Greenfield API key.
    #[arg(long, value_name = "FILE", requires = "btcpay_greenfield_url")]
    btcpay_greenfield_api_key_file: Option<PathBuf>,

    /// BTCPay store observed through Greenfield.
    #[arg(long, value_name = "STORE", requires = "btcpay_greenfield_url")]
    btcpay_greenfield_store: Option<String>,

    /// Bitcoin network associated with Greenfield snapshots.
    #[arg(long, value_name = "NETWORK", requires = "btcpay_greenfield_url")]
    btcpay_greenfield_network: Option<BitcoinNetwork>,

    /// Optional stable node identity overriding the Greenfield-discovered pubkey.
    #[arg(long, value_name = "NODE", requires = "btcpay_greenfield_url")]
    btcpay_greenfield_node: Option<String>,

    /// Greenfield cryptocurrency code.
    #[arg(long, default_value = "BTC", value_name = "CODE")]
    btcpay_greenfield_crypto_code: String,

    /// Seconds between Greenfield polling cycles.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=86_400))]
    btcpay_poll_interval: u64,

    /// Maximum seconds for one complete Greenfield polling cycle.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=300))]
    btcpay_poll_timeout: u64,

    /// Stop polling after this many attempts; zero polls until agent shutdown.
    #[arg(long, default_value_t = 0)]
    btcpay_poll_cycles: u64,

    /// Bitcoin Core JSON-RPC URL for bounded read-only chain observation.
    #[arg(
        long,
        value_name = "URL",
        requires_all = ["bitcoin_core_rpc_user", "bitcoin_core_rpc_password_file"]
    )]
    bitcoin_core_rpc_url: Option<String>,

    /// Bitcoin Core RPC user. Configure this user with a read-only RPC whitelist.
    #[arg(long, value_name = "USER", requires = "bitcoin_core_rpc_url")]
    bitcoin_core_rpc_user: Option<String>,

    /// File containing the Bitcoin Core RPC password.
    #[arg(long, value_name = "FILE", requires = "bitcoin_core_rpc_url")]
    bitcoin_core_rpc_password_file: Option<PathBuf>,

    /// Seconds between Bitcoin Core observation cycles.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=86_400))]
    bitcoin_core_poll_interval: u64,

    /// Maximum seconds for one Bitcoin Core RPC observation.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=300))]
    bitcoin_core_poll_timeout: u64,

    /// Stop Bitcoin Core polling after this many attempts; zero polls until shutdown.
    #[arg(long, default_value_t = 0)]
    bitcoin_core_poll_cycles: u64,

    /// LND REST URL for bounded read-only Lightning observation.
    #[arg(
        long,
        value_name = "URL",
        requires_all = ["lnd_macaroon_file", "lnd_network"]
    )]
    lnd_rest_url: Option<String>,

    /// File containing a scoped, read-only LND macaroon.
    #[arg(long, value_name = "FILE", requires = "lnd_rest_url")]
    lnd_macaroon_file: Option<PathBuf>,

    /// Optional LND TLS certificate in PEM format.
    #[arg(long, value_name = "FILE", requires = "lnd_rest_url")]
    lnd_tls_cert_file: Option<PathBuf>,

    /// Bitcoin network associated with the observed LND node.
    #[arg(long, value_name = "NETWORK", requires = "lnd_rest_url")]
    lnd_network: Option<BitcoinNetwork>,

    /// Allow plaintext LND REST only for local regtest/signet deployments.
    #[arg(long, requires = "lnd_rest_url")]
    lnd_allow_insecure: bool,

    /// Seconds between Lightning observation cycles.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=86_400))]
    lnd_poll_interval: u64,

    /// Maximum seconds for one Lightning observation.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=300))]
    lnd_poll_timeout: u64,

    /// Stop Lightning polling after this many attempts; zero polls until shutdown.
    #[arg(long, default_value_t = 0)]
    lnd_poll_cycles: u64,
}

struct GreenfieldPollConfig {
    adapter: BtcPayAdapter,
    network: BitcoinNetwork,
    detector_node: String,
    interval: Duration,
    timeout: Duration,
    cycles: u64,
}

struct BitcoinCorePollConfig {
    client: BitcoinCoreRpcClient,
    interval: Duration,
    timeout: Duration,
    cycles: u64,
}

struct LndPollConfig {
    adapter: LndAdapter,
    interval: Duration,
    timeout: Duration,
    cycles: u64,
}

/// Owns the long-running Tokio runtime for Rieko's operational agent.
pub fn run(args: AgentArgs) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run_until(args, shutdown_signal()))
}

async fn run_until(
    mut args: AgentArgs,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    apply_connection_config(&mut args)?;
    let db_path = args.db.clone().unwrap_or_else(default_db_path);
    let mut token = load_token(args.token_file.as_deref())?;
    enforce_binding_policy(args.addr, args.allow_external, token.as_deref())?;

    let btcpay_config = match args.btcpay_webhook_secret_file.as_deref() {
        Some(path) => Some((
            load_secret(path, "BTCPay webhook secret")?,
            args.btcpay_network
                .context("--btcpay-network is required with --btcpay-webhook-secret-file")?,
            args.btcpay_node
                .clone()
                .context("--btcpay-node is required with --btcpay-webhook-secret-file")?,
        )),
        None => None,
    };
    let greenfield_config = build_greenfield_poll_config(&args)?;
    let bitcoin_core_config = build_bitcoin_core_poll_config(&args)?;
    let lnd_config = build_lnd_poll_config(&args).await?;

    let storage = SqliteStorage::open(&db_path)
        .with_context(|| format!("opening db {}", db_path.display()))?;
    let _writer = if btcpay_config.is_some()
        || greenfield_config.is_some()
        || bitcoin_core_config.is_some()
        || lnd_config.is_some()
    {
        Some(
            storage
                .writer_lock(&db_path)
                .with_context(|| format!("locking db {}", db_path.display()))?,
        )
    } else {
        None
    };
    let mut api = RiekoApi::new(Box::new(storage))?;
    if let Some(dir) = args.static_dir.as_ref() {
        api = api.with_static_dir(dir);
    }
    if let Some(token) = token.take() {
        api = api.with_auth(token)?;
    }

    let btcpay_worker = btcpay_config.map(|(secret, network, node)| {
        let (sender, receiver) = mpsc::channel(BTCPAY_EVENT_BUFFER);
        api = api.clone().with_btcpay_webhook(secret, sender);
        (receiver, api.state.storage.clone(), network, node)
    });
    let greenfield_storage = api.state.storage.clone();
    let bitcoin_core_storage = api.state.storage.clone();
    let lnd_storage = api.state.storage.clone();

    let app = api.router();
    drop(api);
    let mut webhook_worker = btcpay_worker.map(|(receiver, storage, network, node)| {
        info!(%network, %node, "BTCPay webhook finding pipeline enabled");
        tokio::spawn(run_btcpay_finding_loop(receiver, storage, network, node))
    });
    let (poll_shutdown_tx, poll_shutdown_rx) = watch::channel(false);
    let bitcoin_core_shutdown_rx = poll_shutdown_tx.subscribe();
    let lnd_shutdown_rx = poll_shutdown_tx.subscribe();
    let mut greenfield_worker = greenfield_config.map(|config| {
        info!(
            interval_seconds = config.interval.as_secs(),
            timeout_seconds = config.timeout.as_secs(),
            cycle_limit = config.cycles,
            "BTCPay Greenfield polling enabled"
        );
        tokio::spawn(run_greenfield_poll_loop(
            config,
            greenfield_storage,
            poll_shutdown_rx,
        ))
    });
    let mut bitcoin_core_worker = bitcoin_core_config.map(|config| {
        info!(
            interval_seconds = config.interval.as_secs(),
            timeout_seconds = config.timeout.as_secs(),
            cycle_limit = config.cycles,
            "Bitcoin Core RPC polling enabled"
        );
        tokio::spawn(run_bitcoin_core_poll_loop(
            config,
            bitcoin_core_storage,
            bitcoin_core_shutdown_rx,
        ))
    });
    let mut lnd_worker = lnd_config.map(|config| {
        info!(
            interval_seconds = config.interval.as_secs(),
            timeout_seconds = config.timeout.as_secs(),
            cycle_limit = config.cycles,
            "LND REST polling enabled"
        );
        tokio::spawn(run_lnd_poll_loop(config, lnd_storage, lnd_shutdown_rx))
    });
    let listener = tokio::net::TcpListener::bind(args.addr).await?;
    info!(
        addr = %args.addr,
        behind_proxy = args.behind_proxy,
        static_dir = args.static_dir.as_ref().map(|d| d.display().to_string()),
        "rieko-agent local API listening"
    );
    if args.behind_proxy {
        info!("trusting X-Forwarded-For / X-Real-IP headers from upstream proxy");
    }

    let graceful_shutdown_tx = poll_shutdown_tx.clone();
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.await;
            let _ = graceful_shutdown_tx.send(true);
        })
        .await
        .context("axum serve failed");
    let _ = poll_shutdown_tx.send(true);
    info!("rieko-agent shutdown requested");
    stop_worker(&mut webhook_worker, "BTCPay finding").await;
    stop_worker(&mut greenfield_worker, "BTCPay Greenfield polling").await;
    stop_worker(&mut bitcoin_core_worker, "Bitcoin Core RPC polling").await;
    stop_worker(&mut lnd_worker, "LND REST polling").await;
    result
}

fn apply_connection_config(args: &mut AgentArgs) -> Result<()> {
    let Some(path) = args.config.as_deref() else {
        return Ok(());
    };
    let Some(btcpay) = crate::config::load(path)?.btcpay else {
        return Ok(());
    };
    if args.btcpay_greenfield_url.is_none() {
        args.btcpay_greenfield_url = Some(btcpay.greenfield_base_url);
    }
    if args.btcpay_greenfield_api_key_file.is_none() {
        args.btcpay_greenfield_api_key_file = Some(btcpay.api_key_file);
    }
    if args.btcpay_greenfield_store.is_none() {
        args.btcpay_greenfield_store = Some(btcpay.store_id);
    }
    if args.btcpay_greenfield_network.is_none() {
        args.btcpay_greenfield_network = Some(btcpay.network);
    }
    if args.btcpay_greenfield_node.is_none() {
        args.btcpay_greenfield_node = btcpay.node;
    }
    Ok(())
}

async fn build_lnd_poll_config(args: &AgentArgs) -> Result<Option<LndPollConfig>> {
    let Some(endpoint) = args.lnd_rest_url.as_deref() else {
        return Ok(None);
    };
    let macaroon_file = args
        .lnd_macaroon_file
        .as_deref()
        .context("--lnd-macaroon-file is required with --lnd-rest-url")?;
    let network = args
        .lnd_network
        .context("--lnd-network is required with --lnd-rest-url")?;
    let macaroon = std::fs::read(macaroon_file)
        .with_context(|| format!("reading LND macaroon file {}", macaroon_file.display()))?;
    let tls_cert = args
        .lnd_tls_cert_file
        .as_deref()
        .map(|path| {
            std::fs::read(path)
                .with_context(|| format!("reading LND TLS certificate {}", path.display()))
        })
        .transpose()?;
    let timeout = Duration::from_secs(args.lnd_poll_timeout);
    let endpoint = endpoint.to_owned();
    let allow_insecure = args.lnd_allow_insecure;
    let client = tokio::task::spawn_blocking(move || {
        LndClient::new_with_timeout(endpoint, Some(macaroon), tls_cert, timeout, allow_insecure)
    })
    .await
    .context("joining read-only LND client construction")?
    .context("building read-only LND client")?;
    Ok(Some(LndPollConfig {
        adapter: LndAdapter::new_auto(client, network),
        interval: Duration::from_secs(args.lnd_poll_interval),
        timeout,
        cycles: args.lnd_poll_cycles,
    }))
}

fn build_bitcoin_core_poll_config(args: &AgentArgs) -> Result<Option<BitcoinCorePollConfig>> {
    let Some(endpoint) = args.bitcoin_core_rpc_url.as_deref() else {
        return Ok(None);
    };
    let username = args
        .bitcoin_core_rpc_user
        .clone()
        .context("--bitcoin-core-rpc-user is required with --bitcoin-core-rpc-url")?;
    let password_file = args
        .bitcoin_core_rpc_password_file
        .as_deref()
        .context("--bitcoin-core-rpc-password-file is required with --bitcoin-core-rpc-url")?;
    let password = load_secret(password_file, "Bitcoin Core RPC password")?;
    let timeout = Duration::from_secs(args.bitcoin_core_poll_timeout);
    let client = BitcoinCoreRpcClient::new_with_timeout(endpoint, username, password, timeout)
        .context("building Bitcoin Core RPC client")?;
    Ok(Some(BitcoinCorePollConfig {
        client,
        interval: Duration::from_secs(args.bitcoin_core_poll_interval),
        timeout,
        cycles: args.bitcoin_core_poll_cycles,
    }))
}

fn build_greenfield_poll_config(args: &AgentArgs) -> Result<Option<GreenfieldPollConfig>> {
    let Some(base_url) = args.btcpay_greenfield_url.as_deref() else {
        return Ok(None);
    };
    let api_key_file = args
        .btcpay_greenfield_api_key_file
        .as_deref()
        .context("--btcpay-greenfield-api-key-file is required with --btcpay-greenfield-url")?;
    let store_id = args
        .btcpay_greenfield_store
        .clone()
        .context("--btcpay-greenfield-store is required with --btcpay-greenfield-url")?;
    let network = args
        .btcpay_greenfield_network
        .context("--btcpay-greenfield-network is required with --btcpay-greenfield-url")?;
    let timeout = Duration::from_secs(args.btcpay_poll_timeout);
    let api_key = load_secret(api_key_file, "BTCPay Greenfield API key")?;
    let client = BtcPayGreenfieldClient::new_with_timeout(base_url, api_key, timeout)
        .context("building BTCPay Greenfield client")?;
    let detector_node = format!("btcpay-store:{store_id}");
    let adapter = BtcPayAdapter::new(
        client,
        BtcPayAdapterConfig {
            store_id,
            crypto_code: args.btcpay_greenfield_crypto_code.clone(),
            network,
            node_id_override: args.btcpay_greenfield_node.clone(),
            webhook_secret: None,
        },
    );
    Ok(Some(GreenfieldPollConfig {
        adapter,
        network,
        detector_node,
        interval: Duration::from_secs(args.btcpay_poll_interval),
        timeout,
        cycles: args.btcpay_poll_cycles,
    }))
}

async fn stop_worker(worker: &mut Option<tokio::task::JoinHandle<()>>, label: &str) {
    if let Some(worker) = worker.as_mut() {
        if tokio::time::timeout(WORKER_SHUTDOWN_TIMEOUT, &mut *worker)
            .await
            .is_err()
        {
            warn!(worker = label, "worker did not stop in time; aborting");
            worker.abort();
        }
    }
}

async fn run_greenfield_poll_loop(
    config: GreenfieldPollConfig,
    storage: Arc<Mutex<Box<dyn Storage + Send>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(config.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut attempts = 0_u64;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                attempts += 1;
                if let Err(error) = record_greenfield_attempt(&storage).await {
                    warn!(%error, "failed to persist BTCPay Greenfield polling attempt");
                }

                let poll = async {
                    let health = config.adapter.health_check().await?;
                    if !health.is_connected {
                        bail!(health.message.unwrap_or_else(|| "BTCPay Greenfield is disconnected".into()));
                    }
                    config.adapter.fetch_snapshot().await.map_err(anyhow::Error::new)
                };
                match tokio::time::timeout(config.timeout, poll).await {
                    Ok(Ok(snapshot)) => {
                        let channels = snapshot.channels.len();
                        match persist_greenfield_snapshot(&storage, snapshot).await {
                            Ok(()) => {
                                info!(attempt = attempts, channels, "BTCPay Greenfield snapshot persisted");
                                run_btcpay_health_detector(&storage, config.network, &config.detector_node).await;
                            }
                            Err(error) => warn!(attempt = attempts, %error, "BTCPay Greenfield snapshot persistence failed"),
                        }
                    }
                    Ok(Err(error)) => {
                        warn!(attempt = attempts, %error, "BTCPay Greenfield polling failed");
                        match record_greenfield_failure(&storage).await {
                            Ok(()) => run_btcpay_health_detector(&storage, config.network, &config.detector_node).await,
                            Err(state_error) => warn!(%state_error, "failed to persist BTCPay Greenfield failure state"),
                        }
                    }
                    Err(_) => {
                        warn!(attempt = attempts, timeout_seconds = config.timeout.as_secs(), "BTCPay Greenfield polling timed out");
                        match record_greenfield_failure(&storage).await {
                            Ok(()) => run_btcpay_health_detector(&storage, config.network, &config.detector_node).await,
                            Err(error) => warn!(%error, "failed to persist BTCPay Greenfield timeout state"),
                        }
                    }
                }

                if config.cycles > 0 && attempts >= config.cycles {
                    break;
                }
            }
        }
    }
}

async fn run_bitcoin_core_poll_loop(
    config: BitcoinCorePollConfig,
    storage: Arc<Mutex<Box<dyn Storage + Send>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(config.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut attempts = 0_u64;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                attempts += 1;
                if let Err(error) = record_bitcoin_core_attempt(&storage).await {
                    warn!(%error, "failed to persist Bitcoin Core polling attempt");
                }
                match tokio::time::timeout(config.timeout, config.client.get_blockchain_snapshot()).await {
                    Ok(Ok(snapshot)) => {
                        let network = snapshot.network;
                        let block_height = snapshot.block_height;
                        let header_height = snapshot.header_height;
                        let synchronized = snapshot.synchronized;
                        match record_bitcoin_core_success(&storage, snapshot).await {
                            Ok(()) => {
                                info!(
                                    attempt = attempts,
                                    %network,
                                    block_height,
                                    header_height,
                                    synchronized,
                                    "Bitcoin Core state persisted"
                                );
                                run_bitcoin_core_sync_correlation_detector(&storage).await;
                            }
                            Err(error) => warn!(attempt = attempts, %error, "Bitcoin Core state persistence failed"),
                        }
                    }
                    Ok(Err(error)) => {
                        warn!(attempt = attempts, %error, "Bitcoin Core RPC polling failed");
                        if let Err(state_error) = record_bitcoin_core_failure(&storage).await {
                            warn!(%state_error, "failed to persist Bitcoin Core failure state");
                        }
                    }
                    Err(_) => {
                        warn!(attempt = attempts, timeout_seconds = config.timeout.as_secs(), "Bitcoin Core RPC polling timed out");
                        if let Err(error) = record_bitcoin_core_failure(&storage).await {
                            warn!(%error, "failed to persist Bitcoin Core timeout state");
                        }
                    }
                }

                if config.cycles > 0 && attempts >= config.cycles {
                    break;
                }
            }
        }
    }
}

async fn run_lnd_poll_loop(
    config: LndPollConfig,
    storage: Arc<Mutex<Box<dyn Storage + Send>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let LndPollConfig {
        adapter,
        interval,
        timeout,
        cycles,
    } = config;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut attempts = 0_u64;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                attempts += 1;
                if let Err(error) = record_lnd_attempt(&storage).await {
                    warn!(%error, "failed to persist LND polling attempt");
                }
                match tokio::time::timeout(timeout, adapter.fetch_operational_snapshot()).await {
                    Ok(Ok(snapshot)) => {
                        let node = snapshot.node_id.clone();
                        let synced_to_chain = snapshot.synced_to_chain;
                        let active_channels = snapshot.active_channels;
                        let inactive_channels = snapshot.inactive_channels;
                        match record_lnd_success(&storage, snapshot).await {
                            Ok(()) => {
                                info!(
                                    attempt = attempts,
                                    %node,
                                    synced_to_chain,
                                    active_channels,
                                    inactive_channels,
                                    "Lightning state persisted"
                                );
                                run_lightning_chain_sync_correlation_detector(&storage).await;
                            }
                            Err(error) => warn!(attempt = attempts, %error, "Lightning state persistence failed"),
                        }
                    }
                    Ok(Err(error)) => {
                        warn!(attempt = attempts, %error, "LND REST polling failed");
                        if let Err(state_error) = record_lnd_failure(&storage).await {
                            warn!(%state_error, "failed to persist LND failure state");
                        }
                    }
                    Err(_) => {
                        warn!(attempt = attempts, timeout_seconds = timeout.as_secs(), "LND REST polling timed out");
                        if let Err(error) = record_lnd_failure(&storage).await {
                            warn!(%error, "failed to persist LND timeout state");
                        }
                    }
                }

                if cycles > 0 && attempts >= cycles {
                    break;
                }
            }
        }
    }
    // reqwest's blocking client owns a small internal runtime and must be
    // dropped outside Tokio's async context.
    if let Err(error) = tokio::task::spawn_blocking(move || drop(adapter)).await {
        warn!(%error, "failed to join LND client shutdown");
    }
}

async fn run_btcpay_health_detector(
    storage: &Arc<Mutex<Box<dyn Storage + Send>>>,
    network: BitcoinNetwork,
    node: &str,
) {
    if let Err(error) = evaluate_persisted_btcpay_health(storage, network, node).await {
        warn!(%error, "BTCPay backend-health detector cycle failed");
    }
}

async fn run_bitcoin_core_sync_correlation_detector(storage: &Arc<Mutex<Box<dyn Storage + Send>>>) {
    if let Err(error) = evaluate_persisted_bitcoin_core_sync_correlation(storage).await {
        warn!(%error, "Bitcoin Core sync correlation detector cycle failed");
    }
}

async fn run_lightning_chain_sync_correlation_detector(
    storage: &Arc<Mutex<Box<dyn Storage + Send>>>,
) {
    if let Err(error) = evaluate_persisted_lightning_chain_sync_correlation(storage).await {
        warn!(%error, "Lightning chain-sync correlation detector cycle failed");
    }
}

async fn evaluate_persisted_lightning_chain_sync_correlation(
    storage: &Arc<Mutex<Box<dyn Storage + Send>>>,
) -> Result<()> {
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        let mut storage = storage.blocking_lock();
        let state = storage
            .read_operational_state()
            .map_err(|error| rieko_storage::StorageError::Backend(error.to_string()))?
            .unwrap_or_default();
        let network = state
            .bitcoin_core
            .as_ref()
            .and_then(|core| core.snapshot.as_ref())
            .map_or(BitcoinNetwork::Mainnet, |snapshot| snapshot.network);
        let detector = LightningChainSyncCorrelationDetector::new(state);
        let graph = InMemoryGraph::new();
        let context = DetectorContext {
            node: Some(BTCPAY_CORE_CORRELATION_NODE),
            ..DetectorContext::no_context(network)
        };
        let cycle = detector
            .evaluate(&graph, &context)
            .map_err(|error| rieko_storage::StorageError::Backend(error.to_string()))?;

        persist_operational_detector_cycle(&mut **storage, &cycle)
    })
    .await
    .context("joining Lightning chain-sync correlation detector persistence")??;
    Ok(())
}

async fn evaluate_persisted_bitcoin_core_sync_correlation(
    storage: &Arc<Mutex<Box<dyn Storage + Send>>>,
) -> Result<()> {
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        let mut storage = storage.blocking_lock();
        let state = storage
            .read_operational_state()
            .map_err(|error| rieko_storage::StorageError::Backend(error.to_string()))?
            .unwrap_or_default();
        let network = state
            .bitcoin_core
            .as_ref()
            .and_then(|core| core.snapshot.as_ref())
            .map_or(BitcoinNetwork::Mainnet, |snapshot| snapshot.network);
        let detector = BitcoinCoreSyncCorrelationDetector::new(state);
        let graph = InMemoryGraph::new();
        let context = DetectorContext {
            node: Some(BTCPAY_CORE_CORRELATION_NODE),
            ..DetectorContext::no_context(network)
        };
        let cycle = detector
            .evaluate(&graph, &context)
            .map_err(|error| rieko_storage::StorageError::Backend(error.to_string()))?;

        persist_operational_detector_cycle(&mut **storage, &cycle)
    })
    .await
    .context("joining Bitcoin Core sync correlation detector persistence")??;
    Ok(())
}

fn persist_operational_detector_cycle(
    storage: &mut dyn Storage,
    cycle: &rieko_detectors::DetectorCycle,
) -> Result<usize, rieko_storage::StorageError> {
    storage.begin_transaction()?;
    let result = (|| {
        storage.resolve_findings_for_scope(&cycle.scope)?;
        storage.sync_recommendation_lifecycles()?;
        for finding in &cycle.findings {
            storage.save_finding(finding)?;
        }
        let completed_at = chrono::Utc::now();
        storage
            .update_operational_state(&|state| {
                state.last_cycle_attempt = Some(completed_at);
                state.last_cycle_success = Some(completed_at);
                state.last_persist_success = Some(completed_at);
            })
            .map_err(|error| rieko_storage::StorageError::Backend(error.to_string()))?;
        Ok::<_, rieko_storage::StorageError>(cycle.findings.len())
    })();
    match result {
        Ok(findings) => {
            if let Err(error) = storage.commit_transaction() {
                let _ = storage.rollback_transaction();
                return Err(error);
            }
            Ok(findings)
        }
        Err(error) => {
            let _ = storage.rollback_transaction();
            Err(error)
        }
    }
}

async fn evaluate_persisted_btcpay_health(
    storage: &Arc<Mutex<Box<dyn Storage + Send>>>,
    network: BitcoinNetwork,
    node: &str,
) -> Result<()> {
    let storage = storage.clone();
    let node = node.to_string();
    tokio::task::spawn_blocking(move || {
        let mut storage = storage.blocking_lock();
        let state = storage
            .read_operational_state()
            .map_err(|error| rieko_storage::StorageError::Backend(error.to_string()))?
            .unwrap_or_default();
        let detector = BtcPayBackendHealthDetector::new(state);
        let graph = InMemoryGraph::new();
        let context = DetectorContext {
            node: Some(&node),
            ..DetectorContext::no_context(network)
        };
        let cycle = detector
            .evaluate(&graph, &context)
            .map_err(|error| rieko_storage::StorageError::Backend(error.to_string()))?;

        persist_operational_detector_cycle(&mut **storage, &cycle)
    })
    .await
    .context("joining BTCPay backend-health detector persistence")??;
    Ok(())
}

async fn record_greenfield_attempt(storage: &Arc<Mutex<Box<dyn Storage + Send>>>) -> Result<()> {
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        storage.blocking_lock().update_operational_state(&|state| {
            let connected = matches!(
                state.source,
                rieko_status::SourceState::BtcPayGreenfield { connected: true }
            );
            state.source = rieko_status::SourceState::BtcPayGreenfield { connected };
            state.last_ingestion_attempt = Some(chrono::Utc::now());
        })
    })
    .await
    .context("joining BTCPay Greenfield attempt persistence")??;
    Ok(())
}

async fn record_bitcoin_core_attempt(storage: &Arc<Mutex<Box<dyn Storage + Send>>>) -> Result<()> {
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        storage.blocking_lock().update_operational_state(&|state| {
            let attempted_at = chrono::Utc::now();
            match state.bitcoin_core.as_mut() {
                Some(core) => core.last_attempt = attempted_at,
                None => {
                    state.bitcoin_core = Some(rieko_status::BitcoinCoreState {
                        connected: false,
                        last_attempt: attempted_at,
                        last_success: None,
                        snapshot: None,
                    });
                }
            }
        })
    })
    .await
    .context("joining Bitcoin Core attempt persistence")??;
    Ok(())
}

async fn record_bitcoin_core_success(
    storage: &Arc<Mutex<Box<dyn Storage + Send>>>,
    snapshot: rieko_domain::BitcoinCoreSnapshot,
) -> Result<()> {
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        storage.blocking_lock().update_operational_state(&|state| {
            let completed_at = chrono::Utc::now();
            let last_attempt = state
                .bitcoin_core
                .as_ref()
                .map_or(completed_at, |core| core.last_attempt);
            state.bitcoin_core = Some(rieko_status::BitcoinCoreState {
                connected: true,
                last_attempt,
                last_success: Some(completed_at),
                snapshot: Some(snapshot.clone()),
            });
            state.last_persist_success = Some(completed_at);
        })
    })
    .await
    .context("joining Bitcoin Core success persistence")??;
    Ok(())
}

async fn record_bitcoin_core_failure(storage: &Arc<Mutex<Box<dyn Storage + Send>>>) -> Result<()> {
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        storage.blocking_lock().update_operational_state(&|state| {
            let failed_at = chrono::Utc::now();
            match state.bitcoin_core.as_mut() {
                Some(core) => core.connected = false,
                None => {
                    state.bitcoin_core = Some(rieko_status::BitcoinCoreState {
                        connected: false,
                        last_attempt: failed_at,
                        last_success: None,
                        snapshot: None,
                    });
                }
            }
        })
    })
    .await
    .context("joining Bitcoin Core failure persistence")??;
    Ok(())
}

async fn record_lnd_attempt(storage: &Arc<Mutex<Box<dyn Storage + Send>>>) -> Result<()> {
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        storage.blocking_lock().update_operational_state(&|state| {
            let attempted_at = chrono::Utc::now();
            match state.lightning.as_mut() {
                Some(lightning) => lightning.last_attempt = attempted_at,
                None => {
                    state.lightning = Some(rieko_status::LightningState {
                        connected: false,
                        last_attempt: attempted_at,
                        last_success: None,
                        snapshot: None,
                    });
                }
            }
        })
    })
    .await
    .context("joining LND attempt persistence")??;
    Ok(())
}

async fn record_lnd_success(
    storage: &Arc<Mutex<Box<dyn Storage + Send>>>,
    snapshot: rieko_domain::LightningSnapshot,
) -> Result<()> {
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        storage.blocking_lock().update_operational_state(&|state| {
            let completed_at = chrono::Utc::now();
            let last_attempt = state
                .lightning
                .as_ref()
                .map_or(completed_at, |lightning| lightning.last_attempt);
            state.lightning = Some(rieko_status::LightningState {
                connected: true,
                last_attempt,
                last_success: Some(completed_at),
                snapshot: Some(snapshot.clone()),
            });
            state.last_persist_success = Some(completed_at);
        })
    })
    .await
    .context("joining LND success persistence")??;
    Ok(())
}

async fn record_lnd_failure(storage: &Arc<Mutex<Box<dyn Storage + Send>>>) -> Result<()> {
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        storage.blocking_lock().update_operational_state(&|state| {
            let failed_at = chrono::Utc::now();
            match state.lightning.as_mut() {
                Some(lightning) => lightning.connected = false,
                None => {
                    state.lightning = Some(rieko_status::LightningState {
                        connected: false,
                        last_attempt: failed_at,
                        last_success: None,
                        snapshot: None,
                    });
                }
            }
        })
    })
    .await
    .context("joining LND failure persistence")??;
    Ok(())
}

async fn record_greenfield_failure(storage: &Arc<Mutex<Box<dyn Storage + Send>>>) -> Result<()> {
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        storage.blocking_lock().update_operational_state(&|state| {
            state.source = rieko_status::SourceState::BtcPayGreenfield { connected: false };
        })
    })
    .await
    .context("joining BTCPay Greenfield failure persistence")??;
    Ok(())
}

async fn persist_greenfield_snapshot(
    storage: &Arc<Mutex<Box<dyn Storage + Send>>>,
    snapshot: NodeSnapshot,
) -> Result<()> {
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        let mut storage = storage.blocking_lock();
        storage.begin_transaction()?;
        let result = (|| {
            for mut channel in snapshot.channels {
                channel.state_digest = Some(channel_snapshot_state_digest(&channel));
                storage.save_channel_snapshot(&channel)?;
            }
            let completed_at = chrono::Utc::now();
            storage
                .update_operational_state(&|state| {
                    state.source = rieko_status::SourceState::BtcPayGreenfield { connected: true };
                    state.last_ingestion_success = Some(completed_at);
                    state.last_persist_success = Some(completed_at);
                    state.source_data_at = Some(snapshot.captured_at);
                })
                .map_err(|error| rieko_storage::StorageError::Backend(error.to_string()))?;
            Ok::<_, rieko_storage::StorageError>(())
        })();
        match result {
            Ok(()) => storage.commit_transaction(),
            Err(error) => {
                let _ = storage.rollback_transaction();
                Err(error)
            }
        }
    })
    .await
    .context("joining BTCPay Greenfield snapshot persistence")??;
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        warn!(%error, "failed to install shutdown signal handler");
    }
}

async fn run_btcpay_finding_loop(
    mut receiver: mpsc::Receiver<NodeEvent>,
    storage: Arc<Mutex<Box<dyn Storage + Send>>>,
    network: BitcoinNetwork,
    node: String,
) {
    let detector = SettlementReliabilityDetector::new(node.clone());
    let graph = InMemoryGraph::new();
    let mut events = match reconstruct_btcpay_event_window(&storage).await {
        Ok(events) => events,
        Err(error) => {
            warn!(%error, "failed to reconstruct the BTCPay detector window");
            return;
        }
    };
    info!(
        events = events.len(),
        "BTCPay detector window reconstructed"
    );

    loop {
        if let Err(error) =
            drain_pending_webhook_events(&storage, network, &node, &detector, &graph, &mut events)
                .await
        {
            warn!(%error, "durable BTCPay event replay paused");
        }
        if receiver.recv().await.is_none() {
            let _ = drain_pending_webhook_events(
                &storage,
                network,
                &node,
                &detector,
                &graph,
                &mut events,
            )
            .await;
            break;
        }
    }
}

async fn reconstruct_btcpay_event_window(
    storage: &Arc<Mutex<Box<dyn Storage + Send>>>,
) -> Result<VecDeque<NodeEvent>> {
    let history_storage = storage.clone();
    let history = tokio::task::spawn_blocking(move || {
        history_storage
            .blocking_lock()
            .recent_processed_webhook_events(BTCPAY_DETECTOR_WINDOW as u32)
    })
    .await
    .context("joining processed webhook history query")??;
    let mut events = VecDeque::with_capacity(BTCPAY_DETECTOR_WINDOW);
    for record in history {
        push_settlement_event(&mut events, record.event);
    }
    Ok(events)
}

async fn drain_pending_webhook_events(
    storage: &Arc<Mutex<Box<dyn Storage + Send>>>,
    network: BitcoinNetwork,
    node: &str,
    detector: &SettlementReliabilityDetector,
    graph: &InMemoryGraph,
    events: &mut VecDeque<NodeEvent>,
) -> Result<()> {
    loop {
        let pending_storage = storage.clone();
        let pending = tokio::task::spawn_blocking(move || {
            pending_storage
                .blocking_lock()
                .pending_webhook_events(BTCPAY_DETECTOR_WINDOW as u32)
        })
        .await
        .context("joining pending webhook event query")??;
        if pending.is_empty() {
            return Ok(());
        }
        for record in pending {
            process_pending_webhook_event(storage, network, node, detector, graph, events, record)
                .await?;
        }
    }
}

async fn process_pending_webhook_event(
    storage: &Arc<Mutex<Box<dyn Storage + Send>>>,
    network: BitcoinNetwork,
    node: &str,
    detector: &SettlementReliabilityDetector,
    graph: &InMemoryGraph,
    events: &mut VecDeque<NodeEvent>,
    record: WebhookEventRecord,
) -> Result<()> {
    let previous_window = events.clone();
    let event = record.event;
    push_settlement_event(events, event);

    let window = events.iter().cloned().collect::<Vec<_>>();
    let cycle = {
        let context = DetectorContext {
            network,
            history: None,
            source: None,
            normalizer: None,
            node: Some(node),
            events: Some(&window),
            chain_synchronized: None,
        };
        detector.evaluate(graph, &context)?
    };
    let detector_id = cycle.scope.detector.clone();
    let finding_count = cycle.findings.len();
    let delivery_id = record.delivery_id;
    let persistence_storage = storage.clone();
    let persistence = tokio::task::spawn_blocking(move || {
        let mut storage = persistence_storage.blocking_lock();
        persist_finding_cycle(&mut **storage, &cycle, &delivery_id)
    })
    .await
    .context("joining BTCPay finding persistence task")?;
    if let Err(error) = persistence {
        *events = previous_window;
        return Err(error);
    }
    if finding_count > 0 {
        info!(
            detector = %detector_id,
            findings = finding_count,
            "BTCPay finding cycle persisted"
        );
    }
    Ok(())
}

fn push_settlement_event(events: &mut VecDeque<NodeEvent>, event: NodeEvent) {
    if matches!(
        event,
        NodeEvent::InvoiceSettled(_)
            | NodeEvent::InvoiceExpired(_)
            | NodeEvent::InvoicePaymentReceived(_)
    ) {
        if events.len() == BTCPAY_DETECTOR_WINDOW {
            events.pop_front();
        }
        events.push_back(event);
    }
}

fn persist_finding_cycle(
    storage: &mut dyn Storage,
    cycle: &rieko_detectors::DetectorCycle,
    delivery_id: &str,
) -> Result<()> {
    storage.begin_transaction()?;
    let result = (|| {
        storage.resolve_findings_for_scope(&cycle.scope)?;
        storage.sync_recommendation_lifecycles()?;
        for finding in &cycle.findings {
            storage.save_finding(finding)?;
        }
        storage.mark_webhook_event_processed(delivery_id, chrono::Utc::now())?;
        Ok::<_, rieko_storage::StorageError>(())
    })();

    match result {
        Ok(()) => {
            if let Err(error) = storage.commit_transaction() {
                let _ = storage.rollback_transaction();
                return Err(error.into());
            }
            Ok(())
        }
        Err(error) => {
            let _ = storage.rollback_transaction();
            Err(error.into())
        }
    }
}

fn enforce_binding_policy(
    addr: SocketAddr,
    allow_external: bool,
    token: Option<&str>,
) -> Result<()> {
    if addr.ip().is_loopback() {
        if token.is_some() {
            info!("rieko API will require a bearer token on loopback");
        }
        return Ok(());
    }
    if !allow_external {
        bail!(
            "refusing to bind {addr}: non-loopback address requires --allow-external \
             (external exposure also requires a bearer token)"
        );
    }
    if !token.is_some_and(|value| !value.trim().is_empty()) {
        bail!(
            "refusing to bind {addr}: external exposure requires a bearer token \
             (set --token-file or RIEKO_API_TOKEN)"
        );
    }
    warn!(addr = %addr, "WARNING: rieko API is exposed on a non-loopback address");
    Ok(())
}

fn load_token(file: Option<&Path>) -> Result<Option<String>> {
    if let Some(path) = file {
        return Ok(Some(load_secret(path, "token")?));
    }
    match std::env::var("RIEKO_API_TOKEN") {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value.trim().to_owned())),
        Ok(_) => bail!("RIEKO_API_TOKEN is empty"),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("RIEKO_API_TOKEN is not valid Unicode"),
    }
}

fn load_secret(path: &Path, label: &str) -> Result<String> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading {label} file {}", path.display()))?;
    contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
        .with_context(|| format!("{label} file is empty"))
}

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".rieko").join("rieko.db")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Path as AxumPath;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::Json;
    use chrono::{TimeZone, Utc};
    use rieko_domain::InvoiceExpiredEvent;
    use rieko_storage::MemoryStorage;
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn addr(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    async fn start_mock_btcpay(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), server)
    }

    fn server_info() -> serde_json::Value {
        json!({
            "version": "2.1.0",
            "supportedPaymentMethods": ["BTC", "BTC-LightningNetwork"],
            "fullySynced": true
        })
    }

    fn lightning_info() -> serde_json::Value {
        json!({
            "nodeURIs": ["02abcdef@127.0.0.1:9735"],
            "blockHeight": 850000,
            "activeChannelsCount": 1,
            "inactiveChannelsCount": 0,
            "pendingChannelsCount": 0
        })
    }

    fn lightning_channels() -> serde_json::Value {
        json!([{
            "channelPoint": "txid:0",
            "localBalance": 750000,
            "remoteBalance": 250000,
            "capacity": 1000000,
            "isActive": true
        }])
    }

    fn wallet() -> serde_json::Value {
        json!({
            "balance": 50000,
            "confirmedBalance": 49000,
            "unconfirmedBalance": 1000
        })
    }

    fn greenfield_snapshot_routes(server_info_route: axum::routing::MethodRouter) -> axum::Router {
        axum::Router::new()
            .route("/api/v1/server/info", server_info_route)
            .route(
                "/api/v1/stores/:store/lightning/:crypto/info",
                get(
                    |AxumPath((_store, _crypto)): AxumPath<(String, String)>| async {
                        Json(lightning_info())
                    },
                ),
            )
            .route(
                "/api/v1/stores/:store/lightning/:crypto/channels",
                get(
                    |AxumPath((_store, _crypto)): AxumPath<(String, String)>| async {
                        Json(lightning_channels())
                    },
                ),
            )
            .route(
                "/api/v1/stores/:store/onchain/:crypto/wallet",
                get(
                    |AxumPath((_store, _crypto)): AxumPath<(String, String)>| async {
                        Json(wallet())
                    },
                ),
            )
    }

    fn greenfield_poll_config(
        base_url: &str,
        api_key: &str,
        interval: Duration,
        timeout: Duration,
        cycles: u64,
    ) -> GreenfieldPollConfig {
        let client = BtcPayGreenfieldClient::new_with_timeout(base_url, api_key, timeout).unwrap();
        GreenfieldPollConfig {
            adapter: BtcPayAdapter::new(
                client,
                BtcPayAdapterConfig {
                    store_id: "store-test".into(),
                    crypto_code: "BTC".into(),
                    network: BitcoinNetwork::Regtest,
                    node_id_override: None,
                    webhook_secret: None,
                },
            ),
            network: BitcoinNetwork::Regtest,
            detector_node: "btcpay-store:store-test".into(),
            interval,
            timeout,
            cycles,
        }
    }

    fn memory_storage() -> Arc<Mutex<Box<dyn Storage + Send>>> {
        Arc::new(Mutex::new(Box::new(MemoryStorage::new())))
    }

    async fn run_finite_greenfield_poll(
        config: GreenfieldPollConfig,
    ) -> Arc<Mutex<Box<dyn Storage + Send>>> {
        let storage = memory_storage();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        run_greenfield_poll_loop(config, storage.clone(), shutdown_rx).await;
        storage
    }

    fn bitcoin_core_response() -> serde_json::Value {
        json!({
            "result": {
                "chain": "regtest",
                "blocks": 250,
                "headers": 250,
                "initialblockdownload": false
            },
            "error": null,
            "id": "rieko-core-observation"
        })
    }

    fn bitcoin_core_poll_config(
        endpoint: &str,
        interval: Duration,
        timeout: Duration,
        cycles: u64,
    ) -> BitcoinCorePollConfig {
        BitcoinCorePollConfig {
            client: BitcoinCoreRpcClient::new_with_timeout(endpoint, "rieko", "readonly", timeout)
                .unwrap(),
            interval,
            timeout,
            cycles,
        }
    }

    async fn run_finite_bitcoin_core_poll(
        config: BitcoinCorePollConfig,
    ) -> Arc<Mutex<Box<dyn Storage + Send>>> {
        let storage = memory_storage();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        run_bitcoin_core_poll_loop(config, storage.clone(), shutdown_rx).await;
        storage
    }

    async fn lnd_poll_config(
        endpoint: &str,
        interval: Duration,
        timeout: Duration,
        cycles: u64,
    ) -> LndPollConfig {
        let endpoint = endpoint.to_owned();
        let client = tokio::task::spawn_blocking(move || {
            LndClient::new_with_timeout(
                endpoint,
                Some(vec![0xde, 0xad, 0xbe, 0xef]),
                None,
                timeout,
                true,
            )
            .unwrap()
        })
        .await
        .unwrap();
        LndPollConfig {
            adapter: LndAdapter::new_auto(client, BitcoinNetwork::Regtest),
            interval,
            timeout,
            cycles,
        }
    }

    async fn run_finite_lnd_poll(
        config: LndPollConfig,
        storage: Arc<Mutex<Box<dyn Storage + Send>>>,
    ) -> Arc<Mutex<Box<dyn Storage + Send>>> {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        run_lnd_poll_loop(config, storage.clone(), shutdown_rx).await;
        storage
    }

    fn lnd_info() -> serde_json::Value {
        json!({
            "identity_pubkey": "02abcdef",
            "alias": "rieko-regtest",
            "version": "0.18.5-beta",
            "chains": [{"chain": "bitcoin", "network": "regtest"}],
            "synced_to_chain": true,
            "num_active_channels": 3,
            "num_inactive_channels": 1
        })
    }

    fn healthy_btcpay_core_state(
        observed_at: chrono::DateTime<Utc>,
    ) -> rieko_status::OperationalState {
        rieko_status::OperationalState {
            source: rieko_status::SourceState::BtcPayGreenfield { connected: true },
            bitcoin_core: Some(rieko_status::BitcoinCoreState {
                connected: true,
                last_attempt: observed_at,
                last_success: Some(observed_at),
                snapshot: Some(rieko_domain::BitcoinCoreSnapshot {
                    network: BitcoinNetwork::Regtest,
                    block_height: 250,
                    header_height: 250,
                    synchronized: true,
                    observed_at,
                }),
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn successful_lnd_poll_persists_normalized_state_without_overwriting_other_sources() {
        let requests = Arc::new(AtomicUsize::new(0));
        let observed_requests = requests.clone();
        let app = axum::Router::new().route(
            "/v1/getinfo",
            get(move |headers: HeaderMap| {
                let observed_requests = observed_requests.clone();
                async move {
                    assert_eq!(
                        headers
                            .get("grpc-metadata-macaroon")
                            .and_then(|value| value.to_str().ok()),
                        Some("deadbeef")
                    );
                    observed_requests.fetch_add(1, Ordering::SeqCst);
                    Json(lnd_info())
                }
            }),
        );
        let (endpoint, server) = start_mock_btcpay(app).await;
        let storage = memory_storage();
        let observed_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        storage
            .lock()
            .await
            .write_operational_state(&healthy_btcpay_core_state(observed_at))
            .unwrap();

        let storage = run_finite_lnd_poll(
            lnd_poll_config(
                &endpoint,
                Duration::from_millis(1),
                Duration::from_secs(1),
                2,
            )
            .await,
            storage,
        )
        .await;
        server.abort();

        let mut storage = storage.lock().await;
        let state = storage.read_operational_state().unwrap().unwrap();
        let lightning = state.lightning.unwrap();
        let snapshot = lightning.snapshot.unwrap();
        assert_eq!(
            requests.load(Ordering::SeqCst),
            2,
            "cycle limit must bound polling"
        );
        assert_eq!(
            state.source,
            rieko_status::SourceState::BtcPayGreenfield { connected: true }
        );
        assert!(state.bitcoin_core.unwrap().connected);
        assert!(lightning.connected);
        assert!(lightning.last_success.is_some());
        assert_eq!(snapshot.node_id, "02abcdef");
        assert!(snapshot.synced_to_chain);
        assert_eq!(snapshot.active_channels, 3);
        assert_eq!(snapshot.inactive_channels, 1);
        assert!(storage.latest_findings(10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn lnd_poll_runs_persisted_chain_sync_correlation_detector() {
        let mut response = lnd_info();
        response["synced_to_chain"] = serde_json::Value::Bool(false);
        let app = axum::Router::new().route(
            "/v1/getinfo",
            get(move || {
                let response = response.clone();
                async move { Json(response) }
            }),
        );
        let (endpoint, server) = start_mock_btcpay(app).await;
        let storage = memory_storage();
        storage
            .lock()
            .await
            .write_operational_state(&healthy_btcpay_core_state(
                Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            ))
            .unwrap();

        let storage = run_finite_lnd_poll(
            lnd_poll_config(
                &endpoint,
                Duration::from_millis(1),
                Duration::from_secs(1),
                1,
            )
            .await,
            storage,
        )
        .await;
        server.abort();

        let mut storage = storage.lock().await;
        let findings = storage.latest_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "lightning_chain_sync_correlation");
        assert_eq!(
            findings[0]
                .evidence_value("lightning_state")
                .and_then(|evidence| evidence.get("synced_to_chain")),
            Some(&serde_json::Value::Bool(false))
        );
    }

    #[tokio::test]
    async fn transient_lnd_failure_marks_disconnected_and_preserves_last_snapshot() {
        let requests = Arc::new(AtomicUsize::new(0));
        let observed_requests = requests.clone();
        let app = axum::Router::new().route(
            "/v1/getinfo",
            get(move || {
                let attempt = observed_requests.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        Json(lnd_info()).into_response()
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE.into_response()
                    }
                }
            }),
        );
        let (endpoint, server) = start_mock_btcpay(app).await;
        let storage = run_finite_lnd_poll(
            lnd_poll_config(
                &endpoint,
                Duration::from_millis(1),
                Duration::from_secs(1),
                2,
            )
            .await,
            memory_storage(),
        )
        .await;
        server.abort();

        let state = storage
            .lock()
            .await
            .read_operational_state()
            .unwrap()
            .unwrap();
        let lightning = state.lightning.unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert!(!lightning.connected);
        assert!(lightning.last_success.is_some());
        assert_eq!(lightning.snapshot.unwrap().node_id, "02abcdef");
    }

    #[tokio::test]
    async fn malformed_lnd_response_is_persisted_as_unavailable() {
        let app = axum::Router::new().route(
            "/v1/getinfo",
            get(|| async { Json(json!({"identity_pubkey": 42})) }),
        );
        let (endpoint, server) = start_mock_btcpay(app).await;
        let storage = run_finite_lnd_poll(
            lnd_poll_config(
                &endpoint,
                Duration::from_millis(1),
                Duration::from_secs(1),
                1,
            )
            .await,
            memory_storage(),
        )
        .await;
        server.abort();

        let state = storage
            .lock()
            .await
            .read_operational_state()
            .unwrap()
            .unwrap();
        let lightning = state.lightning.unwrap();
        assert!(!lightning.connected);
        assert!(lightning.last_success.is_none());
        assert!(lightning.snapshot.is_none());
    }

    #[tokio::test]
    async fn successful_bitcoin_core_poll_persists_normalized_state_without_findings() {
        let saw_read_only_auth = Arc::new(AtomicBool::new(false));
        let observed_auth = saw_read_only_auth.clone();
        let app = axum::Router::new().route(
            "/",
            post(move |headers: HeaderMap| {
                let observed_auth = observed_auth.clone();
                async move {
                    observed_auth.store(
                        headers
                            .get(axum::http::header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            == Some("Basic cmlla286cmVhZG9ubHk="),
                        Ordering::SeqCst,
                    );
                    Json(bitcoin_core_response())
                }
            }),
        );
        let (endpoint, server) = start_mock_btcpay(app).await;
        let storage = run_finite_bitcoin_core_poll(bitcoin_core_poll_config(
            &endpoint,
            Duration::from_millis(1),
            Duration::from_secs(1),
            1,
        ))
        .await;
        server.abort();

        let mut storage = storage.lock().await;
        let state = storage.read_operational_state().unwrap().unwrap();
        let core = state.bitcoin_core.unwrap();
        let snapshot = core.snapshot.unwrap();
        assert!(saw_read_only_auth.load(Ordering::SeqCst));
        assert_eq!(state.source, rieko_status::SourceState::Fixture);
        assert!(core.connected);
        assert!(core.last_success.is_some());
        assert_eq!(snapshot.network, BitcoinNetwork::Regtest);
        assert_eq!(snapshot.block_height, 250);
        assert_eq!(snapshot.header_height, 250);
        assert!(snapshot.synchronized);
        assert!(storage.latest_findings(10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn unsynchronized_core_poll_runs_the_persisted_correlation_detector() {
        let response = json!({
            "result": {
                "chain": "regtest",
                "blocks": 240,
                "headers": 250,
                "initialblockdownload": false
            },
            "error": null,
            "id": "rieko-core-observation"
        });
        let app = axum::Router::new().route(
            "/",
            post(move || {
                let response = response.clone();
                async move { Json(response) }
            }),
        );
        let (endpoint, server) = start_mock_btcpay(app).await;
        let storage = memory_storage();
        storage
            .lock()
            .await
            .write_operational_state(&rieko_status::OperationalState {
                source: rieko_status::SourceState::BtcPayGreenfield { connected: true },
                last_ingestion_attempt: Some(Utc.timestamp_opt(1_700_000_000, 0).unwrap()),
                last_ingestion_success: Some(Utc.timestamp_opt(1_700_000_000, 0).unwrap()),
                ..Default::default()
            })
            .unwrap();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        run_bitcoin_core_poll_loop(
            bitcoin_core_poll_config(
                &endpoint,
                Duration::from_millis(1),
                Duration::from_secs(1),
                1,
            ),
            storage.clone(),
            shutdown_rx,
        )
        .await;
        server.abort();

        let mut storage = storage.lock().await;
        let findings = storage.latest_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "bitcoin_core_sync_correlation");
        assert_eq!(
            findings[0]
                .evidence_value("bitcoin_core_state")
                .and_then(|evidence| evidence.get("synchronized")),
            Some(&serde_json::Value::Bool(false))
        );
    }

    async fn assert_failed_bitcoin_core_poll(app: axum::Router) {
        let (endpoint, server) = start_mock_btcpay(app).await;
        let storage = run_finite_bitcoin_core_poll(bitcoin_core_poll_config(
            &endpoint,
            Duration::from_millis(1),
            Duration::from_secs(1),
            1,
        ))
        .await;
        server.abort();

        let mut storage = storage.lock().await;
        let core = storage
            .read_operational_state()
            .unwrap()
            .unwrap()
            .bitcoin_core
            .unwrap();
        assert!(!core.connected);
        assert_eq!(core.last_success, None);
        assert_eq!(core.snapshot, None);
        assert!(storage.latest_findings(10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn bitcoin_core_http_error_is_recorded_without_crashing() {
        let app = axum::Router::new().route(
            "/",
            post(|| async { (StatusCode::SERVICE_UNAVAILABLE, "warming up") }),
        );
        assert_failed_bitcoin_core_poll(app).await;
    }

    #[tokio::test]
    async fn malformed_bitcoin_core_response_is_recorded_without_crashing() {
        let app = axum::Router::new().route("/", post(|| async { "not rpc json" }));
        assert_failed_bitcoin_core_poll(app).await;
    }

    #[tokio::test]
    async fn bitcoin_core_timeout_is_recorded_without_crashing() {
        let app = axum::Router::new().route(
            "/",
            post(|| async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Json(bitcoin_core_response())
            }),
        );
        let (endpoint, server) = start_mock_btcpay(app).await;
        let storage = run_finite_bitcoin_core_poll(bitcoin_core_poll_config(
            &endpoint,
            Duration::from_millis(1),
            Duration::from_millis(10),
            1,
        ))
        .await;
        server.abort();

        let mut storage = storage.lock().await;
        assert!(
            !storage
                .read_operational_state()
                .unwrap()
                .unwrap()
                .bitcoin_core
                .unwrap()
                .connected
        );
        assert!(storage.latest_findings(10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn disconnected_bitcoin_core_is_recorded_without_crashing() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let storage = run_finite_bitcoin_core_poll(bitcoin_core_poll_config(
            &endpoint,
            Duration::from_millis(1),
            Duration::from_millis(100),
            1,
        ))
        .await;
        let mut storage = storage.lock().await;
        assert!(
            !storage
                .read_operational_state()
                .unwrap()
                .unwrap()
                .bitcoin_core
                .unwrap()
                .connected
        );
        assert!(storage.latest_findings(10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn transient_bitcoin_core_failure_recovers_within_bounded_cycles() {
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let app = axum::Router::new().route(
            "/",
            post(move || {
                let request_count = request_count.clone();
                async move {
                    if request_count.fetch_add(1, Ordering::SeqCst) == 0 {
                        (StatusCode::SERVICE_UNAVAILABLE, "warming up").into_response()
                    } else {
                        Json(bitcoin_core_response()).into_response()
                    }
                }
            }),
        );
        let (endpoint, server) = start_mock_btcpay(app).await;
        let started = std::time::Instant::now();
        let storage = run_finite_bitcoin_core_poll(bitcoin_core_poll_config(
            &endpoint,
            Duration::from_millis(20),
            Duration::from_secs(1),
            2,
        ))
        .await;
        server.abort();

        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert!(started.elapsed() >= Duration::from_millis(20));
        let mut storage = storage.lock().await;
        let core = storage
            .read_operational_state()
            .unwrap()
            .unwrap()
            .bitcoin_core
            .unwrap();
        assert!(core.connected);
        assert_eq!(core.snapshot.unwrap().block_height, 250);
        assert!(storage.latest_findings(10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn successful_greenfield_poll_persists_normalized_state_without_findings() {
        let saw_scoped_key = Arc::new(AtomicBool::new(false));
        let key_observation = saw_scoped_key.clone();
        let app = greenfield_snapshot_routes(get(move |headers: HeaderMap| {
            let key_observation = key_observation.clone();
            async move {
                let authorized = headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    == Some("token scoped-read-only-key");
                key_observation.store(authorized, Ordering::SeqCst);
                if authorized {
                    Json(server_info()).into_response()
                } else {
                    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
                }
            }
        }));
        let (base_url, server) = start_mock_btcpay(app).await;
        let storage = run_finite_greenfield_poll(greenfield_poll_config(
            &base_url,
            "scoped-read-only-key",
            Duration::from_millis(1),
            Duration::from_secs(1),
            1,
        ))
        .await;

        server.abort();
        let mut storage = storage.lock().await;
        let snapshots = storage.recent_snapshots_all(10).unwrap();
        let operational = storage.read_operational_state().unwrap().unwrap();
        assert!(saw_scoped_key.load(Ordering::SeqCst));
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].channel_id, "txid:0");
        assert_eq!(snapshots[0].local_balance_msat, 750_000);
        assert_eq!(snapshots[0].remote_balance_msat, 250_000);
        assert_eq!(snapshots[0].network, Some(BitcoinNetwork::Regtest));
        assert_eq!(snapshots[0].node_id.as_deref(), Some("02abcdef"));
        assert!(snapshots[0].state_digest.is_some());
        assert_eq!(
            operational.source,
            rieko_status::SourceState::BtcPayGreenfield { connected: true }
        );
        assert!(operational.last_ingestion_attempt.is_some());
        assert!(operational.last_ingestion_success.is_some());
        assert!(operational.last_persist_success.is_some());
        assert!(operational.source_data_at.is_some());
        assert!(operational.last_cycle_attempt.is_some());
        assert!(operational.last_cycle_success.is_some());
        assert!(storage.latest_findings(10).unwrap().is_empty());
    }

    async fn assert_failed_greenfield_poll(app: axum::Router, timeout: Duration) {
        let (base_url, server) = start_mock_btcpay(app).await;
        let storage = run_finite_greenfield_poll(greenfield_poll_config(
            &base_url,
            "wrong-or-test-key",
            Duration::from_millis(1),
            timeout,
            1,
        ))
        .await;
        server.abort();
        let mut storage = storage.lock().await;
        let operational = storage.read_operational_state().unwrap().unwrap();
        assert_eq!(
            operational.source,
            rieko_status::SourceState::BtcPayGreenfield { connected: false }
        );
        assert!(operational.last_ingestion_attempt.is_some());
        assert_eq!(operational.last_ingestion_success, None);
        assert!(storage.recent_snapshots_all(10).unwrap().is_empty());
        let findings = storage.latest_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "btcpay_backend_health");
        assert_eq!(
            findings[0].evidence_value("operational_state"),
            Some(&serde_json::json!({
                "source": "btcpay_greenfield",
                "connected": false,
                "last_ingestion_attempt": operational.last_ingestion_attempt,
                "last_ingestion_success": null,
            }))
        );
    }

    #[tokio::test]
    async fn greenfield_authentication_failure_is_recorded_without_crashing() {
        let app = greenfield_snapshot_routes(get(|| async {
            (StatusCode::UNAUTHORIZED, "invalid scoped key")
        }));
        assert_failed_greenfield_poll(app, Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn greenfield_timeout_is_recorded_without_crashing() {
        let app = greenfield_snapshot_routes(get(|| async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Json(server_info())
        }));
        assert_failed_greenfield_poll(app, Duration::from_millis(10)).await;
    }

    #[tokio::test]
    async fn malformed_greenfield_response_is_recorded_without_crashing() {
        let app = greenfield_snapshot_routes(get(|| async { "not server info json" }));
        assert_failed_greenfield_poll(app, Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn transient_greenfield_failure_recovers_on_the_next_bounded_cycle() {
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let app = greenfield_snapshot_routes(get(move || {
            let request_count = request_count.clone();
            async move {
                if request_count.fetch_add(1, Ordering::SeqCst) == 0 {
                    (StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable").into_response()
                } else {
                    Json(server_info()).into_response()
                }
            }
        }));
        let (base_url, server) = start_mock_btcpay(app).await;
        let started = std::time::Instant::now();
        let storage = run_finite_greenfield_poll(greenfield_poll_config(
            &base_url,
            "scoped-read-only-key",
            Duration::from_millis(20),
            Duration::from_secs(1),
            2,
        ))
        .await;

        server.abort();
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert!(started.elapsed() >= Duration::from_millis(20));
        let mut storage = storage.lock().await;
        assert_eq!(storage.recent_snapshots_all(10).unwrap().len(), 1);
        assert_eq!(
            storage.read_operational_state().unwrap().unwrap().source,
            rieko_status::SourceState::BtcPayGreenfield { connected: true }
        );
        let findings = storage.latest_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].lifecycle,
            rieko_findings::FindingLifecycle::Active
        );
    }

    #[tokio::test]
    async fn persisted_health_cycles_deduplicate_and_resolve_through_existing_hysteresis() {
        let backends: Vec<Arc<Mutex<Box<dyn Storage + Send>>>> = vec![
            memory_storage(),
            Arc::new(Mutex::new(Box::new(SqliteStorage::in_memory().unwrap()))),
        ];
        for storage in backends {
            {
                let mut storage = storage.lock().await;
                storage
                    .write_operational_state(&rieko_status::OperationalState {
                        source: rieko_status::SourceState::BtcPayGreenfield { connected: false },
                        last_ingestion_attempt: Some(Utc.timestamp_opt(1_700_000_000, 0).unwrap()),
                        ..Default::default()
                    })
                    .unwrap();
            }

            for _ in 0..2 {
                evaluate_persisted_btcpay_health(
                    &storage,
                    BitcoinNetwork::Regtest,
                    "btcpay-store:store-test",
                )
                .await
                .unwrap();
            }
            {
                let mut storage = storage.lock().await;
                let findings = storage.latest_findings(10).unwrap();
                assert_eq!(findings.len(), 1);
                assert_eq!(
                    findings[0].lifecycle,
                    rieko_findings::FindingLifecycle::Active
                );
                storage
                    .update_operational_state(&|state| {
                        state.source =
                            rieko_status::SourceState::BtcPayGreenfield { connected: true };
                        state.last_ingestion_success = state.last_ingestion_attempt;
                    })
                    .unwrap();
            }

            for _ in 0..3 {
                evaluate_persisted_btcpay_health(
                    &storage,
                    BitcoinNetwork::Regtest,
                    "btcpay-store:store-test",
                )
                .await
                .unwrap();
            }

            let mut storage = storage.lock().await;
            let findings = storage.latest_findings(10).unwrap();
            assert_eq!(findings.len(), 1);
            assert_eq!(
                findings[0].lifecycle,
                rieko_findings::FindingLifecycle::Resolved
            );
            assert!(findings[0].evidence_value("operational_state").is_some());
        }
    }

    #[tokio::test]
    async fn persisted_core_correlation_deduplicates_and_resolves_through_existing_hysteresis() {
        let backends: Vec<Arc<Mutex<Box<dyn Storage + Send>>>> = vec![
            memory_storage(),
            Arc::new(Mutex::new(Box::new(SqliteStorage::in_memory().unwrap()))),
        ];
        for storage in backends {
            let observed_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
            storage
                .lock()
                .await
                .write_operational_state(&rieko_status::OperationalState {
                    source: rieko_status::SourceState::BtcPayGreenfield { connected: true },
                    last_ingestion_attempt: Some(observed_at),
                    last_ingestion_success: Some(observed_at),
                    bitcoin_core: Some(rieko_status::BitcoinCoreState {
                        connected: true,
                        last_attempt: observed_at,
                        last_success: Some(observed_at),
                        snapshot: Some(rieko_domain::BitcoinCoreSnapshot {
                            network: BitcoinNetwork::Regtest,
                            block_height: 240,
                            header_height: 250,
                            synchronized: false,
                            observed_at,
                        }),
                    }),
                    ..Default::default()
                })
                .unwrap();

            evaluate_persisted_bitcoin_core_sync_correlation(&storage)
                .await
                .unwrap();
            let first_id = storage.lock().await.latest_findings(10).unwrap()[0]
                .id
                .clone();
            evaluate_persisted_bitcoin_core_sync_correlation(&storage)
                .await
                .unwrap();
            {
                let mut storage = storage.lock().await;
                let findings = storage.latest_findings(10).unwrap();
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].id, first_id);
                assert_eq!(
                    findings[0].lifecycle,
                    rieko_findings::FindingLifecycle::Active
                );
                storage
                    .update_operational_state(&|state| {
                        state
                            .bitcoin_core
                            .as_mut()
                            .and_then(|core| core.snapshot.as_mut())
                            .unwrap()
                            .synchronized = true;
                    })
                    .unwrap();
            }

            for _ in 0..3 {
                evaluate_persisted_bitcoin_core_sync_correlation(&storage)
                    .await
                    .unwrap();
            }

            let mut storage = storage.lock().await;
            let findings = storage.latest_findings(10).unwrap();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].id, first_id);
            assert_eq!(
                findings[0].lifecycle,
                rieko_findings::FindingLifecycle::Resolved
            );
        }
    }

    #[tokio::test]
    async fn persisted_lightning_correlation_deduplicates_and_resolves_through_existing_hysteresis()
    {
        let backends: Vec<Arc<Mutex<Box<dyn Storage + Send>>>> = vec![
            memory_storage(),
            Arc::new(Mutex::new(Box::new(SqliteStorage::in_memory().unwrap()))),
        ];
        for storage in backends {
            let observed_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
            storage
                .lock()
                .await
                .write_operational_state(&rieko_status::OperationalState {
                    source: rieko_status::SourceState::BtcPayGreenfield { connected: true },
                    last_ingestion_attempt: Some(observed_at),
                    last_ingestion_success: Some(observed_at),
                    bitcoin_core: Some(rieko_status::BitcoinCoreState {
                        connected: true,
                        last_attempt: observed_at,
                        last_success: Some(observed_at),
                        snapshot: Some(rieko_domain::BitcoinCoreSnapshot {
                            network: BitcoinNetwork::Regtest,
                            block_height: 250,
                            header_height: 250,
                            synchronized: true,
                            observed_at,
                        }),
                    }),
                    lightning: Some(rieko_status::LightningState {
                        connected: true,
                        last_attempt: observed_at,
                        last_success: Some(observed_at),
                        snapshot: Some(rieko_domain::LightningSnapshot {
                            node_id: "02abcdef".into(),
                            synced_to_chain: false,
                            active_channels: 3,
                            inactive_channels: 1,
                            observed_at,
                        }),
                    }),
                    ..Default::default()
                })
                .unwrap();

            evaluate_persisted_lightning_chain_sync_correlation(&storage)
                .await
                .unwrap();
            let first_id = storage.lock().await.latest_findings(10).unwrap()[0]
                .id
                .clone();
            evaluate_persisted_lightning_chain_sync_correlation(&storage)
                .await
                .unwrap();
            {
                let mut storage = storage.lock().await;
                let findings = storage.latest_findings(10).unwrap();
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].id, first_id);
                assert_eq!(
                    findings[0].lifecycle,
                    rieko_findings::FindingLifecycle::Active
                );
                storage
                    .update_operational_state(&|state| {
                        state
                            .lightning
                            .as_mut()
                            .and_then(|lightning| lightning.snapshot.as_mut())
                            .unwrap()
                            .synced_to_chain = true;
                    })
                    .unwrap();
            }

            for _ in 0..3 {
                evaluate_persisted_lightning_chain_sync_correlation(&storage)
                    .await
                    .unwrap();
            }

            let mut storage = storage.lock().await;
            let findings = storage.latest_findings(10).unwrap();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].id, first_id);
            assert_eq!(
                findings[0].lifecycle,
                rieko_findings::FindingLifecycle::Resolved
            );
        }
    }

    #[derive(clap::Parser)]
    struct TestAgentCli {
        #[command(flatten)]
        args: AgentArgs,
    }

    #[test]
    fn agent_consumes_attached_btcpay_config_and_explicit_flags_keep_precedence() {
        use clap::Parser;

        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("rieko.json");
        let configured_key = directory.path().join("configured.key");
        crate::config::write(
            &config_path,
            &crate::config::RiekoConfig {
                version: crate::config::CONFIG_VERSION,
                btcpay: Some(crate::config::BtcPayConnectionConfig {
                    greenfield_base_url: "https://configured.example".into(),
                    store_id: "configured-store".into(),
                    api_key_file: configured_key.clone(),
                    network: BitcoinNetwork::Regtest,
                    node: Some("configured-node".into()),
                }),
            },
        )
        .unwrap();

        let mut configured = TestAgentCli::try_parse_from([
            "rieko-agent",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .unwrap()
        .args;
        apply_connection_config(&mut configured).unwrap();
        assert_eq!(
            configured.btcpay_greenfield_url.as_deref(),
            Some("https://configured.example")
        );
        assert_eq!(
            configured.btcpay_greenfield_api_key_file.as_ref(),
            Some(&configured_key)
        );
        assert_eq!(
            configured.btcpay_greenfield_store.as_deref(),
            Some("configured-store")
        );
        assert_eq!(
            configured.btcpay_greenfield_network,
            Some(BitcoinNetwork::Regtest)
        );
        assert_eq!(
            configured.btcpay_greenfield_node.as_deref(),
            Some("configured-node")
        );

        let explicit_key = directory.path().join("explicit.key");
        let mut explicit = TestAgentCli::try_parse_from([
            "rieko-agent",
            "--config",
            config_path.to_str().unwrap(),
            "--btcpay-greenfield-url",
            "https://explicit.example",
            "--btcpay-greenfield-api-key-file",
            explicit_key.to_str().unwrap(),
            "--btcpay-greenfield-store",
            "explicit-store",
            "--btcpay-greenfield-network",
            "signet",
            "--btcpay-greenfield-node",
            "explicit-node",
        ])
        .unwrap()
        .args;
        apply_connection_config(&mut explicit).unwrap();
        assert_eq!(
            explicit.btcpay_greenfield_url.as_deref(),
            Some("https://explicit.example")
        );
        assert_eq!(
            explicit.btcpay_greenfield_api_key_file.as_ref(),
            Some(&explicit_key)
        );
        assert_eq!(
            explicit.btcpay_greenfield_store.as_deref(),
            Some("explicit-store")
        );
        assert_eq!(
            explicit.btcpay_greenfield_network,
            Some(BitcoinNetwork::Signet)
        );
        assert_eq!(
            explicit.btcpay_greenfield_node.as_deref(),
            Some("explicit-node")
        );
    }

    #[test]
    fn greenfield_polling_configuration_is_bounded() {
        use clap::Parser;

        let required = [
            "--btcpay-greenfield-url",
            "https://btcpay.example",
            "--btcpay-greenfield-api-key-file",
            "key",
            "--btcpay-greenfield-store",
            "store",
            "--btcpay-greenfield-network",
            "regtest",
        ];
        let mut valid = vec!["rieko-agent"];
        valid.extend(required);
        valid.extend([
            "--btcpay-poll-interval",
            "1",
            "--btcpay-poll-timeout",
            "300",
            "--btcpay-poll-cycles",
            "2",
        ]);
        assert!(TestAgentCli::try_parse_from(valid).is_ok());

        for invalid_tail in [
            ["--btcpay-poll-interval", "0"],
            ["--btcpay-poll-interval", "86401"],
            ["--btcpay-poll-timeout", "0"],
            ["--btcpay-poll-timeout", "301"],
        ] {
            let mut invalid = vec!["rieko-agent"];
            invalid.extend(required);
            invalid.extend(invalid_tail);
            assert!(TestAgentCli::try_parse_from(invalid).is_err());
        }
    }

    #[test]
    fn bitcoin_core_polling_configuration_is_bounded() {
        use clap::Parser;

        let required = [
            "--bitcoin-core-rpc-url",
            "http://127.0.0.1:18443",
            "--bitcoin-core-rpc-user",
            "rieko",
            "--bitcoin-core-rpc-password-file",
            "rpc-password",
        ];
        let mut valid = vec!["rieko-agent"];
        valid.extend(required);
        valid.extend([
            "--bitcoin-core-poll-interval",
            "1",
            "--bitcoin-core-poll-timeout",
            "300",
            "--bitcoin-core-poll-cycles",
            "2",
        ]);
        assert!(TestAgentCli::try_parse_from(valid).is_ok());

        for invalid_tail in [
            ["--bitcoin-core-poll-interval", "0"],
            ["--bitcoin-core-poll-interval", "86401"],
            ["--bitcoin-core-poll-timeout", "0"],
            ["--bitcoin-core-poll-timeout", "301"],
        ] {
            let mut invalid = vec!["rieko-agent"];
            invalid.extend(required);
            invalid.extend(invalid_tail);
            assert!(TestAgentCli::try_parse_from(invalid).is_err());
        }
    }

    #[test]
    fn lnd_polling_configuration_is_bounded_and_requires_read_only_credentials() {
        use clap::Parser;

        let required = [
            "--lnd-rest-url",
            "https://127.0.0.1:8080",
            "--lnd-macaroon-file",
            "readonly.macaroon",
            "--lnd-network",
            "regtest",
        ];
        let mut valid = vec!["rieko-agent"];
        valid.extend(required);
        valid.extend([
            "--lnd-poll-interval",
            "1",
            "--lnd-poll-timeout",
            "300",
            "--lnd-poll-cycles",
            "2",
        ]);
        assert!(TestAgentCli::try_parse_from(valid).is_ok());

        for invalid_tail in [
            ["--lnd-poll-interval", "0"],
            ["--lnd-poll-interval", "86401"],
            ["--lnd-poll-timeout", "0"],
            ["--lnd-poll-timeout", "301"],
        ] {
            let mut invalid = vec!["rieko-agent"];
            invalid.extend(required);
            invalid.extend(invalid_tail);
            assert!(TestAgentCli::try_parse_from(invalid).is_err());
        }

        assert!(TestAgentCli::try_parse_from([
            "rieko-agent",
            "--lnd-rest-url",
            "https://127.0.0.1:8080",
            "--lnd-network",
            "regtest",
        ])
        .is_err());
    }

    #[test]
    fn loopback_bind_succeeds_without_ack_or_token() {
        assert!(enforce_binding_policy(addr("127.0.0.1:8080"), false, None).is_ok());
        assert!(enforce_binding_policy(addr("[::1]:8080"), false, None).is_ok());
    }

    #[test]
    fn loopback_bind_accepts_optional_token() {
        assert!(enforce_binding_policy(addr("127.0.0.1:8080"), false, Some("t")).is_ok());
    }

    #[test]
    fn external_bind_without_ack_fails() {
        let error = enforce_binding_policy(addr("0.0.0.0:8080"), false, None).unwrap_err();
        assert!(error.to_string().contains("--allow-external"));
        let error = enforce_binding_policy(addr("192.168.1.5:8080"), false, Some("t")).unwrap_err();
        assert!(error.to_string().contains("--allow-external"));
    }

    #[test]
    fn external_bind_without_token_fails() {
        let error = enforce_binding_policy(addr("0.0.0.0:8080"), true, None).unwrap_err();
        assert!(error.to_string().contains("bearer token"));
        let error = enforce_binding_policy(addr("0.0.0.0:8080"), true, Some("  ")).unwrap_err();
        assert!(error.to_string().contains("bearer token"));
    }

    #[test]
    fn external_bind_with_ack_and_token_succeeds() {
        assert!(enforce_binding_policy(addr("0.0.0.0:8080"), true, Some("t")).is_ok());
    }

    #[test]
    fn token_loads_from_file_first_nonempty_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "\nsecret-token-value\n").unwrap();
        assert_eq!(
            load_token(Some(&path)).unwrap().as_deref(),
            Some("secret-token-value")
        );
    }

    #[test]
    fn token_loads_from_env_and_file_overrides_env() {
        unsafe {
            std::env::set_var("RIEKO_API_TOKEN", "env-token");
        }
        assert_eq!(load_token(None).unwrap().as_deref(), Some("env-token"));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "file-token\n").unwrap();
        assert_eq!(
            load_token(Some(&path)).unwrap().as_deref(),
            Some("file-token")
        );

        unsafe {
            std::env::set_var("RIEKO_API_TOKEN", " \t ");
        }
        assert!(load_token(None).is_err());
        unsafe {
            std::env::remove_var("RIEKO_API_TOKEN");
        }
    }

    #[tokio::test]
    async fn pending_btcpay_events_replay_into_a_persisted_finding_on_startup() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("restart.db");
        let first_event = NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            id: "invoice-a".into(),
            store_id: Some("store-test".into()),
            amount_msat: None,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        });
        let first_storage: Arc<Mutex<Box<dyn Storage + Send>>> = Arc::new(Mutex::new(Box::new(
            SqliteStorage::open(&database).unwrap(),
        )));
        first_storage
            .lock()
            .await
            .enqueue_webhook_event(
                "delivery-a",
                Some("webhook-test"),
                Some("InvoiceExpired"),
                &first_event,
                Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            )
            .unwrap();
        let (first_sender, first_receiver) = mpsc::channel(1);
        let first_worker = tokio::spawn(run_btcpay_finding_loop(
            first_receiver,
            first_storage.clone(),
            BitcoinNetwork::Regtest,
            "node-test".into(),
        ));
        drop(first_sender);
        first_worker.await.unwrap();
        assert!(first_storage
            .lock()
            .await
            .pending_webhook_events(10)
            .unwrap()
            .is_empty());
        drop(first_storage);

        let mut stopped_storage = SqliteStorage::open(&database).unwrap();
        let second_event = NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            id: "invoice-b".into(),
            store_id: Some("store-test".into()),
            amount_msat: None,
            timestamp: Utc.timestamp_opt(1_700_000_001, 0).unwrap(),
        });
        stopped_storage
            .enqueue_webhook_event(
                "delivery-b",
                Some("webhook-test"),
                Some("InvoiceExpired"),
                &second_event,
                Utc.timestamp_opt(1_700_000_001, 0).unwrap(),
            )
            .unwrap();
        drop(stopped_storage);

        let storage: Arc<Mutex<Box<dyn Storage + Send>>> = Arc::new(Mutex::new(Box::new(
            SqliteStorage::open(&database).unwrap(),
        )));

        let (sender, receiver) = mpsc::channel(4);
        let worker = tokio::spawn(run_btcpay_finding_loop(
            receiver,
            storage.clone(),
            BitcoinNetwork::Regtest,
            "node-test".into(),
        ));
        drop(sender);
        worker.await.unwrap();

        let mut storage = storage.lock().await;
        let findings = storage.latest_findings(10).unwrap();
        assert!(storage.pending_webhook_events(10).unwrap().is_empty());
        assert_eq!(findings.len(), 1);
        let evidence = findings[0]
            .evidence
            .iter()
            .map(|item| (item.key.as_str(), &item.value))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(evidence["root_cause"], "undetermined");
        assert_eq!(
            *evidence["invoice_ids"],
            serde_json::json!(["invoice-a", "invoice-b"])
        );
    }

    #[tokio::test]
    async fn reconstructed_btcpay_window_keeps_only_the_latest_hundred_events() {
        let mut backend = MemoryStorage::new();
        for index in 0..=BTCPAY_DETECTOR_WINDOW {
            let delivery_id = format!("delivery-{index:03}");
            let accepted_at = Utc.timestamp_opt(1_700_000_000 + index as i64, 0).unwrap();
            let event = NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
                id: format!("invoice-{index:03}"),
                store_id: Some("store-test".into()),
                amount_msat: None,
                timestamp: accepted_at,
            });
            backend
                .enqueue_webhook_event(
                    &delivery_id,
                    Some("webhook-test"),
                    Some("InvoiceExpired"),
                    &event,
                    accepted_at,
                )
                .unwrap();
            backend
                .mark_webhook_event_processed(&delivery_id, accepted_at)
                .unwrap();
        }
        let storage: Arc<Mutex<Box<dyn Storage + Send>>> = Arc::new(Mutex::new(Box::new(backend)));

        let window = reconstruct_btcpay_event_window(&storage).await.unwrap();

        assert_eq!(window.len(), BTCPAY_DETECTOR_WINDOW);
        assert!(matches!(
            window.front(),
            Some(NodeEvent::InvoiceExpired(event)) if event.id == "invoice-001"
        ));
        assert!(matches!(
            window.back(),
            Some(NodeEvent::InvoiceExpired(event)) if event.id == "invoice-100"
        ));
    }

    #[tokio::test]
    async fn live_notification_drains_the_durable_queue() {
        let storage: Arc<Mutex<Box<dyn Storage + Send>>> =
            Arc::new(Mutex::new(Box::new(MemoryStorage::new())));
        let (sender, receiver) = mpsc::channel(4);
        let worker = tokio::spawn(run_btcpay_finding_loop(
            receiver,
            storage.clone(),
            BitcoinNetwork::Regtest,
            "node-test".into(),
        ));
        let event = NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            id: "invoice-live".into(),
            store_id: Some("store-test".into()),
            amount_msat: None,
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        });
        storage
            .lock()
            .await
            .enqueue_webhook_event(
                "delivery-live",
                Some("webhook-test"),
                Some("InvoiceExpired"),
                &event,
                Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            )
            .unwrap();
        sender.send(event).await.unwrap();
        drop(sender);
        worker.await.unwrap();

        assert!(storage
            .lock()
            .await
            .pending_webhook_events(10)
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn agent_runtime_stops_when_shutdown_is_requested() {
        let dir = tempfile::tempdir().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let args = AgentArgs {
            config: None,
            db: Some(dir.path().join("agent.db")),
            addr: addr("127.0.0.1:0"),
            static_dir: None,
            allow_external: false,
            token_file: None,
            behind_proxy: false,
            btcpay_webhook_secret_file: None,
            btcpay_network: None,
            btcpay_node: None,
            btcpay_greenfield_url: None,
            btcpay_greenfield_api_key_file: None,
            btcpay_greenfield_store: None,
            btcpay_greenfield_network: None,
            btcpay_greenfield_node: None,
            btcpay_greenfield_crypto_code: "BTC".into(),
            btcpay_poll_interval: 60,
            btcpay_poll_timeout: 10,
            btcpay_poll_cycles: 0,
            bitcoin_core_rpc_url: None,
            bitcoin_core_rpc_user: None,
            bitcoin_core_rpc_password_file: None,
            bitcoin_core_poll_interval: 60,
            bitcoin_core_poll_timeout: 10,
            bitcoin_core_poll_cycles: 0,
            lnd_rest_url: None,
            lnd_macaroon_file: None,
            lnd_tls_cert_file: None,
            lnd_network: None,
            lnd_allow_insecure: false,
            lnd_poll_interval: 60,
            lnd_poll_timeout: 10,
            lnd_poll_cycles: 0,
        };

        let task = tokio::spawn(run_until(args, async {
            let _ = shutdown_rx.await;
        }));
        tokio::task::yield_now().await;
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("agent should stop promptly")
            .unwrap()
            .unwrap();
    }
}
