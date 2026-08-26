use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use reqwest::{StatusCode, Url};
use rieko_findings::{Finding, FindingLifecycle, FindingLifecycleFilter};
use rieko_status::{BitcoinCoreState, OperationalStateStore, SourceState};
use rieko_storage::{SqliteStorage, Storage};
use sha2::{Digest, Sha256};
use tokio::io::copy_bidirectional;
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

const API_TOKEN: &str = "rieko-btcpay-regtest-smoke-token";

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn stop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

struct IsolationProxy {
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl IsolationProxy {
    async fn start(upstream: SocketAddr) -> Self {
        Self::bind("127.0.0.1:0".parse().unwrap(), upstream).await
    }

    async fn restore(address: SocketAddr, upstream: SocketAddr) -> Self {
        Self::bind(address, upstream).await
    }

    async fn bind(address: SocketAddr, upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind(address).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((mut inbound, _)) = accepted else { break };
                        connections.spawn(async move {
                            if let Ok(mut outbound) = TcpStream::connect(upstream).await {
                                let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
                            }
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Self {
            address,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    async fn isolate(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

fn free_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn spawn_agent(
    agent_binary: &str,
    db_path: &Path,
    api_address: SocketAddr,
    token_path: &Path,
    proxy_address: SocketAddr,
    key_path: &Path,
    store_id: &str,
) -> ChildGuard {
    let mut command = configured_agent_command(
        agent_binary,
        db_path,
        api_address,
        token_path,
        proxy_address,
        key_path,
        store_id,
        4,
    );
    ChildGuard(Some(command.spawn().expect("start rieko-agent")))
}

#[allow(clippy::too_many_arguments)]
fn configured_agent_command(
    agent_binary: &str,
    db_path: &Path,
    api_address: SocketAddr,
    token_path: &Path,
    proxy_address: SocketAddr,
    key_path: &Path,
    store_id: &str,
    cycles: u64,
) -> Command {
    let mut command = Command::new(agent_binary);
    command
        .arg("--db")
        .arg(db_path)
        .arg("--addr")
        .arg(api_address.to_string())
        .arg("--token-file")
        .arg(token_path)
        .arg("--btcpay-greenfield-url")
        .arg(format!("http://{proxy_address}"))
        .arg("--btcpay-greenfield-api-key-file")
        .arg(key_path)
        .arg("--btcpay-greenfield-store")
        .arg(store_id)
        .args([
            "--btcpay-greenfield-network",
            "regtest",
            "--btcpay-poll-interval",
            "1",
            "--btcpay-poll-timeout",
            "2",
            "--btcpay-poll-cycles",
            &cycles.to_string(),
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command
}

#[allow(clippy::too_many_arguments)]
fn spawn_correlation_agent(
    agent_binary: &str,
    db_path: &Path,
    api_address: SocketAddr,
    token_path: &Path,
    proxy_address: SocketAddr,
    key_path: &Path,
    store_id: &str,
    core_password_path: &Path,
) -> ChildGuard {
    let mut command = configured_agent_command(
        agent_binary,
        db_path,
        api_address,
        token_path,
        proxy_address,
        key_path,
        store_id,
        10,
    );
    command
        .arg("--bitcoin-core-rpc-url")
        .arg(required_env("BITCOIN_CORE_RPC_URL"))
        .arg("--bitcoin-core-rpc-user")
        .arg(required_env("RPC_READONLY_USER"))
        .arg("--bitcoin-core-rpc-password-file")
        .arg(core_password_path)
        .args([
            "--bitcoin-core-poll-interval",
            "1",
            "--bitcoin-core-poll-timeout",
            "2",
            "--bitcoin-core-poll-cycles",
            "10",
        ]);
    ChildGuard(Some(command.spawn().expect("start rieko-agent")))
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be configured by regtest.yml"))
}

fn bitcoin_cli_result(method: &str, arguments: &[&str]) -> Result<String, String> {
    let rpc_user = required_env("RPC_USER");
    let rpc_password = required_env("RPC_PASS");
    let output = Command::new("docker")
        .args(["exec", "bitcoind", "bitcoin-cli", "-regtest"])
        .arg(format!("-rpcuser={rpc_user}"))
        .arg(format!("-rpcpassword={rpc_password}"))
        .arg(method)
        .args(arguments)
        .output()
        .map_err(|error| format!("run bitcoin-cli: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "bitcoin-cli {method} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map(|output| output.trim().to_string())
        .map_err(|error| format!("bitcoin-cli output is not UTF-8: {error}"))
}

fn bitcoin_cli(method: &str, arguments: &[&str]) -> String {
    bitcoin_cli_result(method, arguments).unwrap_or_else(|error| panic!("{error}"))
}

fn blockchain_info() -> serde_json::Value {
    serde_json::from_str(&bitcoin_cli("getblockchaininfo", &[]))
        .expect("getblockchaininfo returns JSON")
}

struct CoreHeaderGap {
    restored: bool,
}

impl CoreHeaderGap {
    fn induce() -> (Self, u64, u64) {
        let before = blockchain_info();
        assert_eq!(before["chain"], "regtest");
        assert_eq!(before["blocks"], before["headers"]);
        assert_eq!(before["initialblockdownload"], false);

        let header = mine_next_regtest_header();
        bitcoin_cli("submitheader", &[&header]);
        let guard = Self { restored: false };
        let degraded = blockchain_info();
        let blocks = degraded["blocks"].as_u64().expect("numeric block height");
        let headers = degraded["headers"].as_u64().expect("numeric header height");
        assert!(
            blocks < headers,
            "submitting a header without its block must create a header gap"
        );
        assert_eq!(degraded["initialblockdownload"], false);

        (guard, blocks, headers)
    }

    fn restore(&mut self) {
        if !self.restored {
            bitcoin_cli("-rpcwallet=default", &["-generate", "2"]);
            self.restored = true;
        }
    }
}

impl Drop for CoreHeaderGap {
    fn drop(&mut self) {
        if !self.restored {
            let _ = bitcoin_cli_result("-rpcwallet=default", &["-generate", "2"]);
            self.restored = true;
        }
    }
}

fn mine_next_regtest_header() -> String {
    let template: serde_json::Value = serde_json::from_str(&bitcoin_cli(
        "getblocktemplate",
        &[r#"{"rules":["segwit"]}"#],
    ))
    .expect("getblocktemplate returns JSON");
    let version = template["version"].as_u64().expect("template version") as u32;
    let mut previous = decode_hex(
        template["previousblockhash"]
            .as_str()
            .expect("template previous block hash"),
    );
    previous.reverse();
    let timestamp = template["curtime"].as_u64().expect("template time") as u32;
    let bits_text = template["bits"].as_str().expect("template compact target");
    let bits = u32::from_str_radix(bits_text, 16).expect("hex compact target");
    let target = compact_target(bits);

    let mut header = Vec::with_capacity(80);
    header.extend_from_slice(&version.to_le_bytes());
    header.extend_from_slice(&previous);
    header.extend_from_slice(&[0_u8; 32]);
    header.extend_from_slice(&timestamp.to_le_bytes());
    header.extend_from_slice(&bits.to_le_bytes());
    header.extend_from_slice(&0_u32.to_le_bytes());

    for nonce in 0..=u32::MAX {
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        let first = Sha256::digest(&header);
        let second = Sha256::digest(first);
        let hash_as_big_endian = second.iter().rev().copied().collect::<Vec<_>>();
        if hash_as_big_endian.as_slice() <= target.as_slice() {
            return encode_hex(&header);
        }
    }
    panic!("regtest header nonce space unexpectedly exhausted");
}

fn compact_target(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    assert!((3..=32).contains(&exponent), "supported compact target");
    let mut target = [0_u8; 32];
    let offset = 32 - exponent;
    target[offset] = (mantissa >> 16) as u8;
    target[offset + 1] = (mantissa >> 8) as u8;
    target[offset + 2] = mantissa as u8;
    target
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex has an even length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).expect("valid hex")
        })
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    use std::fmt::Write as _;

    value.iter().fold(
        String::with_capacity(value.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        },
    )
}

async fn upstream_address(base_url: &str) -> SocketAddr {
    let url = Url::parse(base_url).expect("BTCPAY_GREENFIELD_URL must be a URL");
    assert_eq!(
        url.scheme(),
        "http",
        "the isolation smoke test requires an HTTP endpoint inside a trusted regtest network"
    );
    assert!(
        url.path().is_empty() || url.path() == "/",
        "BTCPAY_GREENFIELD_URL must not contain a path"
    );
    let host = url.host_str().expect("BTCPAY_GREENFIELD_URL needs a host");
    let port = url.port_or_known_default().unwrap();
    let address = lookup_host((host, port))
        .await
        .expect("resolve BTCPay regtest host")
        .next()
        .expect("BTCPay regtest host resolved to no addresses");
    address
}

async fn wait_for_healthy_source(client: &reqwest::Client, api_url: &str) {
    for _ in 0..100 {
        if let Ok(response) = client
            .get(format!("{api_url}/status"))
            .bearer_auth(API_TOKEN)
            .send()
            .await
        {
            if let Ok(status) = response.json::<serde_json::Value>().await {
                if status["source"] == "btcpay-greenfield (connected)" {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("rieko-agent never persisted a healthy BTCPay Greenfield state");
}

async fn wait_for_initial_correlation_state(db_path: &Path) -> BitcoinCoreState {
    for _ in 0..100 {
        if let Ok(storage) = SqliteStorage::open(db_path) {
            if let Ok(Some(state)) = storage.read_operational_state() {
                if state.source == (SourceState::BtcPayGreenfield { connected: true }) {
                    if let Some(core) = state.bitcoin_core {
                        if core.connected
                            && core
                                .snapshot
                                .as_ref()
                                .is_some_and(|snapshot| snapshot.synchronized)
                        {
                            return core;
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("agent did not persist synchronized Core and reachable BTCPay state");
}

async fn wait_for_active_core_correlation(client: &reqwest::Client, api_url: &str) -> Finding {
    for _ in 0..150 {
        if let Ok(response) = client
            .get(format!("{api_url}/findings?limit=50"))
            .bearer_auth(API_TOKEN)
            .send()
            .await
        {
            if let Ok(findings) = response.json::<Vec<Finding>>().await {
                let correlation = findings
                    .into_iter()
                    .filter(|finding| finding.detector == "bitcoin_core_sync_correlation")
                    .collect::<Vec<_>>();
                if correlation.len() == 1
                    && correlation[0].lifecycle == FindingLifecycle::Active
                    && correlation[0]
                        .last_seen_at
                        .signed_duration_since(correlation[0].first_seen_at)
                        .num_milliseconds()
                        >= 1_500
                {
                    return correlation.into_iter().next().unwrap();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("bounded Core polling did not persist one stable active correlation finding");
}

async fn wait_for_restarted_disconnected_source(client: &reqwest::Client, api_url: &str) {
    for _ in 0..100 {
        if let Ok(response) = client
            .get(format!("{api_url}/status"))
            .bearer_auth(API_TOKEN)
            .send()
            .await
        {
            if let Ok(status) = response.json::<serde_json::Value>().await {
                if status["source"] == "btcpay-greenfield (disconnected)" {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("restarted rieko-agent did not reopen the disconnected operational state");
}

async fn wait_for_three_degraded_cycles(client: &reqwest::Client, api_url: &str) -> Vec<Finding> {
    for _ in 0..120 {
        let response = client
            .get(format!("{api_url}/findings?limit=50"))
            .bearer_auth(API_TOKEN)
            .send()
            .await;
        if let Ok(response) = response {
            if let Ok(findings) = response.json::<Vec<Finding>>().await {
                let health = findings
                    .iter()
                    .filter(|finding| finding.detector == "btcpay_backend_health")
                    .collect::<Vec<_>>();
                if health.len() == 1
                    && health[0]
                        .last_seen_at
                        .signed_duration_since(health[0].first_seen_at)
                        .num_milliseconds()
                        >= 1_500
                {
                    return findings;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("three bounded degraded health cycles did not complete");
}

async fn wait_for_resolved_finding(
    client: &reqwest::Client,
    api_url: &str,
    finding_id: &str,
) -> Finding {
    for _ in 0..120 {
        let response = client
            .get(format!("{api_url}/findings/{finding_id}"))
            .bearer_auth(API_TOKEN)
            .send()
            .await;
        if let Ok(response) = response {
            if let Ok(finding) = response.json::<Finding>().await {
                if finding.lifecycle == FindingLifecycle::Resolved {
                    return finding;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("three bounded healthy recovery cycles did not resolve the finding");
}

async fn live_flow() {
    let base_url = std::env::var("BTCPAY_GREENFIELD_URL")
        .expect("BTCPAY_GREENFIELD_URL must point to a real BTCPay regtest deployment");
    let api_key = std::env::var("BTCPAY_GREENFIELD_API_KEY")
        .expect("BTCPAY_GREENFIELD_API_KEY must contain a scoped read-only key");
    let store_id = std::env::var("BTCPAY_GREENFIELD_STORE")
        .expect("BTCPAY_GREENFIELD_STORE must identify the configured regtest store");

    let upstream = upstream_address(&base_url).await;
    let proxy = IsolationProxy::start(upstream).await;
    let proxy_address = proxy.address;
    let api_address = free_address();
    let api_url = format!("http://{api_address}");
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("rieko.db");
    let key_path = temp.path().join("btcpay-readonly.key");
    let token_path = temp.path().join("rieko-api.token");
    std::fs::write(&key_path, format!("{api_key}\n")).unwrap();
    std::fs::write(&token_path, format!("{API_TOKEN}\n")).unwrap();

    let agent_binary = std::env::var("CARGO_BIN_EXE_rieko-agent")
        .expect("Cargo did not provide the rieko-agent integration-test binary path");
    let mut agent = spawn_agent(
        &agent_binary,
        &db_path,
        api_address,
        &token_path,
        proxy_address,
        &key_path,
        &store_id,
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    wait_for_healthy_source(&client, &api_url).await;

    // The proxy has forwarded real Greenfield responses up to this point.
    // Closing it now drops active connections and makes the endpoint
    // deterministically unreachable without modifying BTCPay itself.
    proxy.isolate().await;

    let unauthorized = client
        .get(format!("{api_url}/findings"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let findings = wait_for_three_degraded_cycles(&client, &api_url).await;
    let health = findings
        .iter()
        .filter(|finding| finding.detector == "btcpay_backend_health")
        .collect::<Vec<_>>();
    assert_eq!(health.len(), 1, "one stable logical health finding");
    assert_eq!(
        health[0].evidence_value("operational_state"),
        Some(&serde_json::json!({
            "source": "btcpay_greenfield",
            "connected": false,
            "last_ingestion_attempt": health[0].last_seen_at,
            "last_ingestion_success": health[0]
                .evidence_value("operational_state")
                .and_then(|value| value.get("last_ingestion_success"))
                .cloned()
                .unwrap(),
        }))
    );
    let active_id = health[0].id.clone();

    agent.stop();
    agent = spawn_agent(
        &agent_binary,
        &db_path,
        api_address,
        &token_path,
        proxy_address,
        &key_path,
        &store_id,
    );
    wait_for_restarted_disconnected_source(&client, &api_url).await;

    let active_after_restart = client
        .get(format!("{api_url}/findings?limit=50"))
        .bearer_auth(API_TOKEN)
        .send()
        .await
        .unwrap()
        .json::<Vec<Finding>>()
        .await
        .unwrap()
        .into_iter()
        .filter(|finding| finding.detector == "btcpay_backend_health")
        .collect::<Vec<_>>();
    assert_eq!(active_after_restart.len(), 1);
    assert_eq!(active_after_restart[0].id, active_id);
    assert_eq!(active_after_restart[0].lifecycle, FindingLifecycle::Active);

    // Rebind the same proxy address to the unchanged real BTCPay upstream.
    // The restarted agent keeps the original Greenfield URL and recovers the
    // finding loaded from the same SQLite database.
    let restored_proxy = IsolationProxy::restore(proxy_address, upstream).await;
    let resolved = wait_for_resolved_finding(&client, &api_url, &active_id).await;
    assert_eq!(
        resolved.id, active_id,
        "recovery preserves logical identity"
    );
    assert_eq!(resolved.detector, "btcpay_backend_health");
    assert_eq!(resolved.lifecycle, FindingLifecycle::Resolved);

    let active_after_recovery = client
        .get(format!("{api_url}/findings?limit=50"))
        .bearer_auth(API_TOKEN)
        .send()
        .await
        .unwrap()
        .json::<Vec<Finding>>()
        .await
        .unwrap()
        .into_iter()
        .filter(|finding| finding.detector == "btcpay_backend_health")
        .collect::<Vec<_>>();
    assert!(
        active_after_recovery.is_empty(),
        "resolved health finding is absent from the active collection"
    );

    agent.stop();
    restored_proxy.isolate().await;
    let mut storage = SqliteStorage::open(&db_path).unwrap();
    let operational = storage.read_operational_state().unwrap().unwrap();
    assert_eq!(
        operational.source,
        SourceState::BtcPayGreenfield { connected: true }
    );
    let persisted = storage
        .latest_findings_by_lifecycle(50, FindingLifecycleFilter::All)
        .unwrap()
        .into_iter()
        .filter(|finding| finding.detector == "btcpay_backend_health")
        .collect::<Vec<_>>();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].id, active_id);
    assert_eq!(persisted[0].lifecycle, FindingLifecycle::Resolved);
}

async fn live_core_sync_correlation_flow() {
    let base_url = required_env("BTCPAY_GREENFIELD_URL");
    let api_key = required_env("BTCPAY_GREENFIELD_API_KEY");
    let store_id = required_env("BTCPAY_GREENFIELD_STORE");
    let core_password = required_env("RPC_READONLY_PASS");

    let upstream = upstream_address(&base_url).await;
    let proxy = IsolationProxy::start(upstream).await;
    let api_address = free_address();
    let api_url = format!("http://{api_address}");
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("rieko-correlation.db");
    let key_path = temp.path().join("btcpay-readonly.key");
    let core_password_path = temp.path().join("core-readonly.password");
    let token_path = temp.path().join("rieko-api.token");
    std::fs::write(&key_path, format!("{api_key}\n")).unwrap();
    std::fs::write(&core_password_path, format!("{core_password}\n")).unwrap();
    std::fs::write(&token_path, format!("{API_TOKEN}\n")).unwrap();

    let agent_binary = required_env("CARGO_BIN_EXE_rieko-agent");
    let mut agent = spawn_correlation_agent(
        &agent_binary,
        &db_path,
        api_address,
        &token_path,
        proxy.address,
        &key_path,
        &store_id,
        &core_password_path,
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    let initial_core = wait_for_initial_correlation_state(&db_path).await;
    assert!(initial_core.connected);
    assert!(initial_core.snapshot.unwrap().synchronized);

    let (mut header_gap, expected_blocks, expected_headers) = CoreHeaderGap::induce();

    let unauthorized = client
        .get(format!("{api_url}/findings"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let finding = wait_for_active_core_correlation(&client, &api_url).await;
    assert_eq!(finding.lifecycle, FindingLifecycle::Active);
    assert_eq!(
        finding.evidence_value("btcpay_state").unwrap()["connected"],
        true
    );
    let core_evidence = finding.evidence_value("bitcoin_core_state").unwrap();
    assert_eq!(core_evidence["connected"], true);
    assert_eq!(core_evidence["network"], "regtest");
    assert_eq!(core_evidence["block_height"], expected_blocks);
    assert_eq!(core_evidence["header_height"], expected_headers);
    assert_eq!(core_evidence["synchronized"], false);

    let detail = client
        .get(format!("{api_url}/findings/{}", finding.id))
        .bearer_auth(API_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Finding>()
        .await
        .unwrap();
    assert_eq!(detail, finding);

    agent.stop();
    proxy.isolate().await;

    let mut storage = SqliteStorage::open(&db_path).unwrap();
    let operational = storage.read_operational_state().unwrap().unwrap();
    assert_eq!(
        operational.source,
        SourceState::BtcPayGreenfield { connected: true }
    );
    let persisted_core = operational.bitcoin_core.unwrap();
    assert!(persisted_core.connected);
    let persisted_snapshot = persisted_core.snapshot.unwrap();
    assert_eq!(persisted_snapshot.network.to_string(), "regtest");
    assert_eq!(persisted_snapshot.block_height, expected_blocks);
    assert_eq!(persisted_snapshot.header_height, expected_headers);
    assert!(!persisted_snapshot.synchronized);

    let persisted = storage
        .latest_findings_by_lifecycle(50, FindingLifecycleFilter::All)
        .unwrap()
        .into_iter()
        .filter(|candidate| candidate.detector == "bitcoin_core_sync_correlation")
        .collect::<Vec<_>>();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0], finding);

    header_gap.restore();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a real BTCPay regtest deployment; see docs/testing-btcpay-regtest.md"]
async fn real_btcpay_greenfield_restart_continuity_resolves_the_same_finding() {
    tokio::time::timeout(Duration::from_secs(30), live_flow())
        .await
        .expect("live BTCPay health smoke test exceeded its 30-second bound");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the real BTCPay and Bitcoin Core regtest deployment in regtest.yml"]
async fn real_btcpay_and_unsynchronized_core_emit_persisted_correlation_finding() {
    tokio::time::timeout(Duration::from_secs(30), live_core_sync_correlation_flow())
        .await
        .expect("live BTCPay/Core correlation smoke test exceeded its 30-second bound");
}
