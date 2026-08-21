use chrono::Utc;
use rieko_detectors::registry::{Detector, DetectorContext};
use rieko_detectors::SettlementReliabilityDetector;
use rieko_domain::{
    BitcoinNetwork, Channel, ChannelId, ChannelStatus, FeePolicy, InvoiceExpiredEvent,
    InvoiceSettledEvent, LiquidityProfile, NodeEvent, NodeId,
};
use rieko_findings::{
    ActionStage, ActionType, Actionability, FindingLifecycle, ObservationSource, ProducerRole,
    ProducerVersion, Severity,
};
use rieko_graph::{GraphStore, InMemoryGraph};
use rieko_recommendations::RecommendationEngine;
use rieko_storage::{SqliteStorage, Storage};

fn create_channel(id: &str, node: &NodeId, local_msat: u64, capacity_msat: u64) -> Channel {
    Channel {
        id: ChannelId::new(id),
        node: node.clone(),
        peer: NodeId::new("03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        channel_point: "2222222222222222222222222222222222222222222222222222222222222222:1".into(),
        capacity_msat,
        fee_policy: FeePolicy::default(),
        status: ChannelStatus::Active,
        liquidity: LiquidityProfile::compute(
            capacity_msat,
            local_msat,
            capacity_msat.saturating_sub(local_msat),
        ),
        last_seen: Utc::now(),
        opening_height: Some(830000),
        local_reserve_msat: None,
        remote_reserve_msat: None,
        is_private: false,
        is_initiator: true,
        total_received_msat: Some(50_000_000),
        total_sent_msat: Some(950_000_000),
    }
}

#[test]
fn lightning_settlement_reliability_degradation_e2e_pipeline() {
    let local_node_str = "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let local_node = NodeId::new(local_node_str);

    // 1. Ingest LND Channel State (drained merchant channel)
    let drained_channel_id = "800000x100x1";
    let drained_channel = create_channel(
        drained_channel_id,
        &local_node,
        25_000_000,    // 25m sat local balance
        1_000_000_000, // 1000m sat capacity -> local_ratio = 0.025 (heavily drained)
    );

    let mut graph = InMemoryGraph::new();
    graph.upsert_channels(vec![drained_channel]).unwrap();

    // 2. Ingest BTCPay Temporal Webhook Events (4 expired invoices, 1 settled invoice)
    let events = vec![
        NodeEvent::InvoiceSettled(InvoiceSettledEvent {
            id: "btcpay-inv-101".into(),
            store_id: Some("merchant-store-main".into()),
            payment_method: Some("BTC-LightningLike".into()),
            amount_msat: 50_000_000,
            fee_msat: 250,
            timestamp: Utc::now(),
            payment_hash: Some("hash1".into()),
            metadata: std::collections::HashMap::new(),
        }),
        NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            id: "btcpay-inv-102".into(),
            store_id: Some("merchant-store-main".into()),
            amount_msat: Some(100_000_000),
            timestamp: Utc::now(),
        }),
        NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            id: "btcpay-inv-103".into(),
            store_id: Some("merchant-store-main".into()),
            amount_msat: Some(250_000_000),
            timestamp: Utc::now(),
        }),
        NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            id: "btcpay-inv-104".into(),
            store_id: Some("merchant-store-main".into()),
            amount_msat: Some(80_000_000),
            timestamp: Utc::now(),
        }),
        NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            id: "btcpay-inv-105".into(),
            store_id: Some("merchant-store-main".into()),
            amount_msat: Some(150_000_000),
            timestamp: Utc::now(),
        }),
    ]; // 4 expired / 5 total = 80.0% failure rate -> Critical severity

    // 3. Setup observation context with BTCPay source and Bitcoin Core synchronized = true
    let btcpay_source = ObservationSource::BtcPay {
        redacted_endpoint:
            "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069".into(),
        configured_store: "merchant-store-main".into(),
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
        chain_synchronized: Some(true), // Bitcoin Core node is verified synchronized!
    };

    // 4. Run SettlementReliabilityDetector
    let detector = SettlementReliabilityDetector::new(local_node.clone());
    let cycle = detector
        .evaluate(&graph, &ctx)
        .expect("detector cycle should evaluate cleanly");

    assert!(cycle.scope.complete);
    assert_eq!(cycle.findings.len(), 1);

    let finding = &cycle.findings[0];
    assert_eq!(finding.detector, "settlement_reliability");
    assert_eq!(finding.detector_version, "1");
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.node.as_deref(), Some(local_node_str));
    assert_eq!(finding.channel.as_deref(), Some(drained_channel_id));
    assert_eq!(finding.lifecycle, FindingLifecycle::Active);

    // Verify structured evidence
    let ev_map: std::collections::HashMap<_, _> = finding
        .evidence
        .iter()
        .map(|e| (e.key.as_str(), &e.value))
        .collect();

    assert_eq!(ev_map.get("expired_invoices").unwrap(), &4.0);
    assert_eq!(ev_map.get("settled_invoices").unwrap(), &1.0);
    assert_eq!(ev_map.get("total_invoices").unwrap(), &5.0);
    assert_eq!(ev_map.get("failure_rate").unwrap(), &0.80);
    assert_eq!(ev_map.get("drained_channels_count").unwrap(), &1.0);
    assert_eq!(ev_map.get("chain_synchronized").unwrap(), &"true");
    assert_eq!(
        ev_map.get("root_cause").unwrap(),
        &"lightning_operational_degradation"
    );
    assert_eq!(
        ev_map.get("diagnosis").unwrap(),
        &"lightning_settlement_degraded"
    );

    // 5. Verify Recommendation Engine produces concrete operator actions
    let engine = RecommendationEngine;
    let recommendations = engine
        .recommend(finding)
        .expect("recommendation should succeed");
    assert_eq!(recommendations.len(), 1);

    let rec = &recommendations[0];
    assert_eq!(rec.finding_id, finding.id);
    assert_eq!(rec.action.action_type, ActionType::RebalanceChannel);
    assert_eq!(rec.action.stage, ActionStage::Recommended);
    assert_eq!(rec.action.target.as_deref(), Some(drained_channel_id));
    assert!(rec.action.summary.contains(drained_channel_id));
    assert!(rec.action.summary.contains("80.0% failure rate"));
    assert_eq!(
        rec.rationale.actionability,
        Actionability::OperatorActionable
    );
    assert!(!rec.rationale.preconditions.is_empty());
    assert!(!rec.rationale.risks.is_empty());

    // 6. Test durable SQLite persistence of the operational finding and recommendation
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("rieko_operational.db");
    let mut storage = SqliteStorage::open(&db_path).unwrap();

    for f in &cycle.findings {
        storage.save_finding(f).unwrap();
    }
    for r in &recommendations {
        storage.save_recommendation(r).unwrap();
    }

    let loaded_findings = storage
        .latest_findings_by_lifecycle(10, rieko_findings::FindingLifecycleFilter::Active)
        .unwrap();
    assert_eq!(loaded_findings.len(), 1);
    assert_eq!(loaded_findings[0].id, finding.id);
    assert_eq!(loaded_findings[0].detector, "settlement_reliability");

    let loaded_recs = storage.latest_recommendations(10).unwrap();
    assert_eq!(loaded_recs.len(), 1);
    assert_eq!(loaded_recs[0].finding_id, finding.id);
    assert_eq!(
        loaded_recs[0].action.target.as_deref(),
        Some(drained_channel_id)
    );
}
