use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use reqwest::{StatusCode, Url};
use rieko_findings::{Finding, FindingLifecycle, FindingLifecycleFilter};
use rieko_status::{OperationalStateStore, SourceState};
use rieko_storage::{SqliteStorage, Storage};
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
    let mut agent = ChildGuard(Some(
        Command::new(agent_binary)
            .args([
                "--db",
                db_path.to_str().unwrap(),
                "--addr",
                &api_address.to_string(),
                "--token-file",
                token_path.to_str().unwrap(),
                "--btcpay-greenfield-url",
                &format!("http://{}", proxy.address),
                "--btcpay-greenfield-api-key-file",
                key_path.to_str().unwrap(),
                "--btcpay-greenfield-store",
                &store_id,
                "--btcpay-greenfield-network",
                "regtest",
                "--btcpay-poll-interval",
                "1",
                "--btcpay-poll-timeout",
                "2",
                "--btcpay-poll-cycles",
                "7",
            ])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start rieko-agent"),
    ));

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

    // Rebind the same proxy address to the unchanged real BTCPay upstream.
    // The agent keeps its original Greenfield URL and observes recovery without
    // being restarted or reconfigured.
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a real BTCPay regtest deployment; see docs/testing-btcpay-regtest.md"]
async fn real_btcpay_greenfield_failure_and_recovery_reaches_authenticated_findings_api() {
    tokio::time::timeout(Duration::from_secs(30), live_flow())
        .await
        .expect("live BTCPay health smoke test exceeded its 30-second bound");
}
