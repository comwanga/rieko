use rieko_domain::{BitcoinNetwork, NodeIngestionAdapter};
use rieko_ingest_lnd::{LndAdapter, LndClient};

#[tokio::test]
async fn live_regtest_adapter_fetches_snapshot() {
    let Ok(rest) = std::env::var("LND_REST") else {
        // Skipped in environments without a running LND instance.
        return;
    };
    let tls_path =
        std::env::var("LND_TLS_CERT").expect("LND_TLS_CERT required when LND_REST is set");
    let mac_path =
        std::env::var("LND_MACAROON").expect("LND_MACAROON required when LND_REST is set");

    let tls_cert = std::fs::read(&tls_path)
        .unwrap_or_else(|e| panic!("failed to read TLS cert from {tls_path}: {e}"));
    let macaroon = std::fs::read(&mac_path)
        .unwrap_or_else(|e| panic!("failed to read macaroon from {mac_path}: {e}"));

    let client = LndClient::new(rest, Some(macaroon), Some(tls_cert))
        .expect("LndClient::new must accept valid TLS cert and macaroon");
    let adapter = LndAdapter::new_auto(client, BitcoinNetwork::Regtest);

    // 1. Verify health_check executes against live /v1/getinfo over TLS with macaroon
    let health = adapter.health_check().await.expect("health check");
    assert!(
        health.is_connected,
        "health_check must report connected for live LND node: {:?}",
        health.message
    );
    assert_eq!(health.source_name, "lnd");

    // 2. Verify fetch_snapshot derives identity from GetInfo and fetches channel snapshot
    let snapshot = adapter.fetch_snapshot().await.expect("fetch snapshot");
    assert!(
        !snapshot.node_id.is_empty(),
        "node_id must be populated from live GetInfo identity_pubkey"
    );
    assert_ne!(
        snapshot.node_id, "local-node",
        "node_id must be the real LND pubkey, not fallback default"
    );
    assert_eq!(snapshot.network, BitcoinNetwork::Regtest);
}
