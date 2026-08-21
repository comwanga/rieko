use axum::extract::Path;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use rieko_domain::{BitcoinNetwork, ChannelStatus, NodeIngestionAdapter};
use rieko_ingest_btcpay::{
    BtcPayAdapter, BtcPayAdapterConfig, BtcPayGreenfieldClient,
};
use serde_json::json;
use tokio::net::TcpListener;

async fn mock_server_info() -> impl IntoResponse {
    Json(json!({
        "version": "2.0.0",
        "supportedPaymentMethods": ["BTC", "BTC-LightningNetwork"],
        "fullySynced": true
    }))
}

async fn mock_lightning_info(Path((_store_id, _crypto)): Path<(String, String)>) -> impl IntoResponse {
    Json(json!({
        "nodeURIs": ["02112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00@127.0.0.1:9735"],
        "blockHeight": 850000,
        "alias": "btcpay-node",
        "color": "#00ff00",
        "version": "v0.18.0",
        "activeChannelsCount": 2,
        "inactiveChannelsCount": 1,
        "pendingChannelsCount": 0
    }))
}

async fn mock_lightning_balance(Path((_store_id, _crypto)): Path<(String, String)>) -> impl IntoResponse {
    Json(json!({
        "total": 5000000,
        "local": 3000000,
        "remote": 2000000,
        "unsettled": 0
    }))
}

async fn mock_lightning_channels(Path((_store_id, _crypto)): Path<(String, String)>) -> impl IntoResponse {
    Json(json!([
        {
            "channelPoint": "1111111111111111111111111111111111111111111111111111111111111111:0",
            "localBalance": 2000000,
            "remoteBalance": 1000000,
            "capacity": 3000000,
            "isActive": true
        },
        {
            "channelPoint": "2222222222222222222222222222222222222222222222222222222222222222:1",
            "localBalance": 1000000,
            "remoteBalance": 1000000,
            "capacity": 2000000,
            "isActive": true
        },
        {
            "channelPoint": "3333333333333333333333333333333333333333333333333333333333333333:0",
            "localBalance": 0,
            "remoteBalance": 500000,
            "capacity": 500000,
            "isActive": false
        }
    ]))
}

async fn mock_onchain_wallet(Path((_store_id, _crypto)): Path<(String, String)>) -> impl IntoResponse {
    Json(json!({
        "balance": 1500000,
        "confirmedBalance": 1500000,
        "unconfirmedBalance": 0
    }))
}

#[tokio::test]
async fn polls_greenfield_into_normalized_node_snapshot() {
    let app = Router::new()
        .route("/api/v1/server/info", get(mock_server_info))
        .route(
            "/api/v1/stores/:store_id/lightning/:crypto/info",
            get(mock_lightning_info),
        )
        .route(
            "/api/v1/stores/:store_id/lightning/:crypto/balance",
            get(mock_lightning_balance),
        )
        .route(
            "/api/v1/stores/:store_id/lightning/:crypto/channels",
            get(mock_lightning_channels),
        )
        .route(
            "/api/v1/stores/:store_id/onchain/:crypto/wallet",
            get(mock_onchain_wallet),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let base_url = format!("http://{}", addr);
    let client = BtcPayGreenfieldClient::new(&base_url, "test-token").unwrap();

    let config = BtcPayAdapterConfig {
        store_id: "store-test-1".into(),
        crypto_code: "BTC".into(),
        network: BitcoinNetwork::Regtest,
        node_id_override: None,
        webhook_secret: None,
    };

    let adapter = BtcPayAdapter::new(client, config);

    // Test health check
    let health = adapter.health_check().await.expect("health check passes");
    assert!(health.is_connected);
    assert_eq!(health.source_name, "btcpay");

    // Test snapshot fetch and normalization
    let snapshot = adapter.fetch_snapshot().await.expect("fetch_snapshot passes");
    assert_eq!(snapshot.network, BitcoinNetwork::Regtest);
    assert_eq!(snapshot.active_channels_count, 2);
    assert_eq!(snapshot.inactive_channels_count, 1);
    assert_eq!(snapshot.total_local_balance_msat, 3_000_000);
    assert_eq!(snapshot.total_remote_balance_msat, 2_000_000);
    assert_eq!(snapshot.total_capacity_msat, 5_500_000);
    assert_eq!(snapshot.block_height, Some(850000));
    assert_eq!(snapshot.onchain_balance_sats, Some(1500000));
    assert_eq!(snapshot.channels.len(), 3);

    let c0 = &snapshot.channels[0];
    assert_eq!(c0.status, ChannelStatus::Active);
    assert_eq!(c0.local_balance_msat, 2_000_000);
    assert_eq!(c0.remote_balance_msat, 1_000_000);
}
