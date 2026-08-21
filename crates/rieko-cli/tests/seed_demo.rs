use chrono::Utc;
use rieko_detectors::registry::{Detector, DetectorContext};
use rieko_detectors::SettlementReliabilityDetector;
use rieko_domain::{
    BitcoinNetwork, Channel, ChannelId, ChannelStatus, FeePolicy, InvoiceExpiredEvent,
    InvoiceSettledEvent, LiquidityProfile, NodeEvent, NodeId,
};
use rieko_findings::{ObservationSource, ProducerRole, ProducerVersion};
use rieko_graph::{GraphStore, InMemoryGraph};
use rieko_recommendations::RecommendationEngine;
use rieko_storage::{SqliteStorage, Storage};
use std::path::PathBuf;

#[test]
fn seed_demo_database() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let target_dir = workspace_root.join("target");
    std::fs::create_dir_all(&target_dir).unwrap();
    let db_path = target_dir.join("demo_operational.db");

    if db_path.exists() {
        let _ = std::fs::remove_file(&db_path);
    }

    let mut storage = SqliteStorage::open(&db_path).expect("open sqlite db");

    let local_node_str = "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let local_node = NodeId::new(local_node_str);
    let bottleneck_channel_id = "800000x100x1";

    let channel = Channel {
        id: ChannelId::new(bottleneck_channel_id),
        node: local_node.clone(),
        peer: NodeId::new("03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        channel_point: "2222222222222222222222222222222222222222222222222222222222222222:1".into(),
        capacity_msat: 1_000_000_000,
        fee_policy: FeePolicy::default(),
        status: ChannelStatus::Active,
        liquidity: LiquidityProfile::compute(1_000_000_000, 25_000_000, 975_000_000), // 0.025 local ratio
        last_seen: Utc::now(),
        opening_height: Some(830000),
        local_reserve_msat: None,
        remote_reserve_msat: None,
        is_private: false,
        is_initiator: true,
        total_received_msat: Some(50_000_000),
        total_sent_msat: Some(950_000_000),
    };

    let mut graph = InMemoryGraph::new();
    graph.upsert_channels(vec![channel.clone()]).unwrap();

    let events = vec![
        NodeEvent::InvoiceSettled(InvoiceSettledEvent {
            id: "inv-101".into(),
            store_id: Some("btcpay-store-merchant".into()),
            payment_method: Some("BTC-LightningLike".into()),
            amount_msat: 50_000_000,
            fee_msat: 250,
            timestamp: Utc::now(),
            payment_hash: Some("hash1".into()),
            metadata: std::collections::HashMap::new(),
        }),
        NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            id: "inv-102".into(),
            store_id: Some("btcpay-store-merchant".into()),
            amount_msat: Some(100_000_000),
            timestamp: Utc::now(),
        }),
        NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            id: "inv-103".into(),
            store_id: Some("btcpay-store-merchant".into()),
            amount_msat: Some(250_000_000),
            timestamp: Utc::now(),
        }),
        NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            id: "inv-104".into(),
            store_id: Some("btcpay-store-merchant".into()),
            amount_msat: Some(80_000_000),
            timestamp: Utc::now(),
        }),
        NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            id: "inv-105".into(),
            store_id: Some("btcpay-store-merchant".into()),
            amount_msat: Some(150_000_000),
            timestamp: Utc::now(),
        }),
    ]; // 80% failure rate

    let btcpay_source = ObservationSource::BtcPay {
        redacted_endpoint:
            "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069".into(),
        configured_store: "btcpay-store-merchant".into(),
        underlying_node: Some(local_node_str.into()),
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
        node: Some(local_node_str),
        events: Some(&events),
        chain_synchronized: Some(true),
    };

    let detector = SettlementReliabilityDetector::new(local_node.clone());
    let cycle = detector.evaluate(&graph, &ctx).expect("evaluate detector");

    let engine = RecommendationEngine;
    for finding in &cycle.findings {
        storage.save_finding(finding).unwrap();
        let recs = engine.recommend(finding).unwrap();
        for rec in recs {
            storage.save_recommendation(&rec).unwrap();
        }
    }

    let snapshot =
        rieko_domain::ChannelSnapshot::from_channel(&channel, Utc::now(), BitcoinNetwork::Mainnet);
    storage.save_channel_snapshot(&snapshot).unwrap();

    println!("Seeded demo database successfully at {:?}", db_path);
}
