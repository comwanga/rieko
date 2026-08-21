use chrono::Utc;
use rieko_detectors::liquidity::LiquidityDetector;
use rieko_detectors::registry::{Detector, DetectorContext};
use rieko_domain::{
    BitcoinNetwork, Channel, ChannelId, ChannelSnapshot, ChannelStatus, FeePolicy,
    LiquidityProfile, NodeEvent, NodeId, NodeIngestionAdapter, NodeSnapshot,
};
use rieko_findings::{ObservationSource, ProducerRole, ProducerVersion};
use rieko_graph::{GraphStore, InMemoryGraph};
use rieko_ingest_btcpay::{
    normalize_webhook_payload, verify_btcpay_sig, BtcPayAdapter, BtcPayAdapterConfig,
    BtcPayGreenfieldClient,
};
use rieko_ingest_lnd::{LndAdapter, LndClient};
use rieko_recommendations::RecommendationEngine;

#[test]
fn full_operational_pipeline_btcpay_lnd_webhooks_to_recommendations() {
    let now = Utc::now();
    let local_node_id = NodeId::new("node-merchant-hub");
    let customer_node_id = NodeId::new("node-mobile-shopper");
    let lsp_node_id = NodeId::new("node-liquidity-provider");

    // -------------------------------------------------------------------------
    // 1. Adapter Abstraction: Verify both BtcPayAdapter and LndAdapter implement NodeIngestionAdapter
    // -------------------------------------------------------------------------
    let btcpay_client =
        BtcPayGreenfieldClient::new("https://btcpay.example.com", "test-token").unwrap();
    let btcpay_config = BtcPayAdapterConfig {
        store_id: "store-apparel-01".into(),
        crypto_code: "BTC".into(),
        network: BitcoinNetwork::Mainnet,
        node_id_override: Some("node-merchant-hub".into()),
        webhook_secret: Some("production-secure-webhook-secret-99".into()),
    };
    let btcpay_adapter: Box<dyn NodeIngestionAdapter> =
        Box::new(BtcPayAdapter::new(btcpay_client, btcpay_config));
    assert_eq!(btcpay_adapter.source_name(), "btcpay");

    let lnd_client = LndClient::new("https://127.0.0.1:8080", None, None).unwrap();
    let lnd_adapter: Box<dyn NodeIngestionAdapter> = Box::new(LndAdapter::new(
        lnd_client,
        local_node_id.clone(),
        BitcoinNetwork::Mainnet,
    ));
    assert_eq!(lnd_adapter.source_name(), "lnd");

    // -------------------------------------------------------------------------
    // 2. Multi-Source Ingestion: BTCPay Greenfield snapshot + LND snapshot
    // -------------------------------------------------------------------------
    // Channel 1 (BTCPay merchant store channel): local 30,000,000 / capacity 1,000,000,000 (0.03 local ratio -> Critical)
    let btcpay_channel = Channel {
        id: ChannelId::new("btcpay-store-chan-01"),
        node: local_node_id.clone(),
        peer: customer_node_id.clone(),
        channel_point: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef:0".into(),
        capacity_msat: 1_000_000_000,
        fee_policy: FeePolicy::default(),
        status: ChannelStatus::Active,
        liquidity: LiquidityProfile::compute(1_000_000_000, 30_000_000, 970_000_000),
        last_seen: now,
        opening_height: Some(840000),
        local_reserve_msat: None,
        remote_reserve_msat: None,
        is_private: false,
        is_initiator: false,
        total_received_msat: Some(970_000_000),
        total_sent_msat: Some(30_000_000),
    };

    // Channel 2 (LND LSP routing channel): local 900,000,000 / capacity 1,000,000,000 (0.90 local ratio)
    let lnd_channel = Channel {
        id: ChannelId::new("lnd-lsp-chan-02"),
        node: local_node_id.clone(),
        peer: lsp_node_id.clone(),
        channel_point: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890:1".into(),
        capacity_msat: 1_000_000_000,
        fee_policy: FeePolicy::default(),
        status: ChannelStatus::Active,
        liquidity: LiquidityProfile::compute(1_000_000_000, 900_000_000, 100_000_000),
        last_seen: now,
        opening_height: Some(840010),
        local_reserve_msat: None,
        remote_reserve_msat: None,
        is_private: false,
        is_initiator: true,
        total_received_msat: Some(100_000_000),
        total_sent_msat: Some(900_000_000),
    };

    let snapshot_btcpay = NodeSnapshot::from_channels(
        "node-merchant-hub",
        BitcoinNetwork::Mainnet,
        vec![ChannelSnapshot::from_channel(
            &btcpay_channel,
            now,
            BitcoinNetwork::Mainnet,
        )],
        now,
        Some(840050),
        Some(50_000_000),
    );
    assert_eq!(snapshot_btcpay.active_channels_count, 1);

    let snapshot_lnd = NodeSnapshot::from_channels(
        "node-merchant-hub",
        BitcoinNetwork::Mainnet,
        vec![ChannelSnapshot::from_channel(
            &lnd_channel,
            now,
            BitcoinNetwork::Mainnet,
        )],
        now,
        Some(840050),
        Some(100_000_000),
    );
    assert_eq!(snapshot_lnd.active_channels_count, 1);

    // -------------------------------------------------------------------------
    // 3. Webhook Delivery & Normalization
    // -------------------------------------------------------------------------
    let webhook_secret = "production-secure-webhook-secret-99";
    let webhook_body = br#"{
        "deliveryId": "del-prod-invoice-42",
        "webhookId": "wh-merchant-01",
        "type": "InvoiceSettled",
        "timestamp": 1724250000,
        "storeId": "store-apparel-01",
        "invoiceId": "inv-premium-hoodie-001",
        "paymentMethod": "BTC-LightningNetwork",
        "payment": {
            "value": "2500000",
            "fee": "250",
            "paymentHash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        }
    }"#;

    // HMAC verification with sha256= prefix
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes()).unwrap();
    mac.update(webhook_body);
    let sig_header = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

    assert!(verify_btcpay_sig(
        webhook_secret.as_bytes(),
        webhook_body,
        &sig_header
    ));

    // Normalize into strongly typed NodeEvent
    let event = normalize_webhook_payload(webhook_body).expect("normalization succeeds");
    match &event {
        NodeEvent::InvoiceSettled(e) => {
            assert_eq!(e.id, "inv-premium-hoodie-001");
            assert_eq!(e.store_id.as_deref(), Some("store-apparel-01"));
            assert_eq!(e.amount_msat, 2_500_000);
            assert_eq!(e.fee_msat, 250);
        }
        other => panic!("expected InvoiceSettled, got {:?}", other),
    }

    // -------------------------------------------------------------------------
    // 4. Merge Multi-Source State into Unified Domain Graph
    // -------------------------------------------------------------------------
    let mut graph = InMemoryGraph::new();
    graph
        .upsert_channels(vec![btcpay_channel, lnd_channel])
        .expect("graph channels merged");

    // -------------------------------------------------------------------------
    // 5. Deterministic Detector Pipeline Execution
    // -------------------------------------------------------------------------
    let btcpay_source = ObservationSource::BtcPay {
        redacted_endpoint: "sha256:endpoint-digest".into(),
        configured_store: "store-apparel-01".into(),
        underlying_node: Some("node-merchant-hub".into()),
    };

    let normalizer = ProducerVersion {
        name: "rieko-ingest-btcpay".into(),
        version: "0.1.0".into(),
        role: ProducerRole::Normalizer,
    };

    let ctx = DetectorContext {
        network: BitcoinNetwork::Mainnet,
        history: None,
        source: Some(&btcpay_source),
        normalizer: Some(&normalizer),
        node: Some("node-merchant-hub"),
    };

    let detector = LiquidityDetector::new(local_node_id.clone());
    let findings = detector.run(&graph, &ctx);

    // Finding generated for drained BTCPay channel
    let critical_finding = findings
        .iter()
        .find(|f| f.channel.as_deref() == Some("btcpay-store-chan-01"))
        .expect("must detect drained BTCPay channel");

    assert_eq!(critical_finding.detector, "channel_liquidity");
    assert_eq!(
        critical_finding.severity,
        rieko_findings::Severity::Critical
    );
    assert_eq!(
        critical_finding.provenance.as_ref().map(|p| &p.source),
        Some(&btcpay_source)
    );

    // -------------------------------------------------------------------------
    // 6. Recommendation Engine: Generates Actionable Recommendation
    // -------------------------------------------------------------------------
    let engine = RecommendationEngine;
    let recs = engine
        .recommend(critical_finding)
        .expect("recommendation succeeds");
    assert!(!recs.is_empty(), "must produce at least 1 recommendation");

    let rec = &recs[0];
    assert_eq!(rec.finding_id, critical_finding.id);
    assert_eq!(rec.action.target.as_deref(), Some("btcpay-store-chan-01"));
}
