use chrono::Utc;
use rieko_detectors::liquidity::LiquidityDetector;
use rieko_detectors::registry::{Detector, DetectorContext};
use rieko_domain::{
    BitcoinNetwork, Channel, ChannelId, ChannelStatus, FeePolicy, LiquidityProfile, NodeId,
};
use rieko_findings::{ObservationSource, ProducerRole, ProducerVersion};
use rieko_graph::{GraphStore, InMemoryGraph};
use rieko_recommendations::RecommendationEngine;

#[test]
fn correlates_btcpay_and_lnd_operational_evidence_into_typed_findings() {
    let now = Utc::now();
    let local_node = NodeId::new("node-alpha");
    let peer_btcpay = NodeId::new("peer-store-customer");
    let peer_lnd = NodeId::new("peer-lnd-routing");

    // 1. Channel 1: Observed via BTCPay Server Greenfield (heavily drained outbound on store lightning node)
    let chan_btcpay = Channel {
        id: ChannelId::new("btcpay-chan-101"),
        node: local_node.clone(),
        peer: peer_btcpay,
        channel_point: "1111111111111111111111111111111111111111111111111111111111111111:0".into(),
        capacity_msat: 1_000_000_000,
        fee_policy: FeePolicy::default(),
        status: ChannelStatus::Active,
        // Drained outbound: 20,000,000 msat local (0.02 ratio), 980,000,000 msat remote
        liquidity: LiquidityProfile::compute(1_000_000_000, 20_000_000, 980_000_000),
        last_seen: now,
        opening_height: Some(800000),
        local_reserve_msat: None,
        remote_reserve_msat: None,
        is_private: false,
        is_initiator: false,
        total_received_msat: Some(0),
        total_sent_msat: Some(0),
    };

    // 2. Channel 2: Observed via direct LND node connection (outbound-heavy routing channel)
    let chan_lnd = Channel {
        id: ChannelId::new("lnd-chan-202"),
        node: local_node.clone(),
        peer: peer_lnd,
        channel_point: "2222222222222222222222222222222222222222222222222222222222222222:1".into(),
        capacity_msat: 1_000_000_000,
        fee_policy: FeePolicy::default(),
        status: ChannelStatus::Active,
        // Outbound drained (warning): 80,000,000 msat local (0.08 ratio), 920,000,000 msat remote
        liquidity: LiquidityProfile::compute(1_000_000_000, 80_000_000, 920_000_000),
        last_seen: now,
        opening_height: Some(800050),
        local_reserve_msat: None,
        remote_reserve_msat: None,
        is_private: false,
        is_initiator: false,
        total_received_msat: Some(0),
        total_sent_msat: Some(0),
    };

    // 3. Load both channels into the unified in-memory graph
    let mut graph = InMemoryGraph::new();
    graph
        .upsert_channels(vec![chan_btcpay, chan_lnd])
        .expect("upsert succeeds");

    // 4. Provenance tracking with BTCPay source specifying the underlying node
    let btcpay_source = ObservationSource::BtcPay {
        redacted_endpoint: "sha256:btcpay-server-endpoint".into(),
        configured_store: "store-merchant-42".into(),
        underlying_node: Some("node-alpha".into()),
    };

    let normalizer = ProducerVersion {
        name: "rieko-ingest-btcpay".into(),
        version: "0.1.0".into(),
        role: ProducerRole::Normalizer,
    };

    let ctx = DetectorContext {
        network: BitcoinNetwork::Regtest,
        history: None,
        source: Some(&btcpay_source),
        normalizer: Some(&normalizer),
        node: Some("node-alpha"),
    };

    // 5. Run pure deterministic liquidity detector (no LLM, no I/O)
    let detector = LiquidityDetector::new(local_node.clone());
    let findings = detector.run(&graph, &ctx);

    // Verify exactly 2 findings generated:
    // - 1 Critical finding for the severely drained BTCPay channel
    // - 1 Warning finding for the outbound-heavy LND channel
    assert_eq!(
        findings.len(),
        2,
        "expected findings for both imbalanced channels"
    );

    let btcpay_finding = findings
        .iter()
        .find(|f| f.channel.as_deref() == Some("btcpay-chan-101"))
        .expect("BTCPay channel finding must exist");
    assert_eq!(btcpay_finding.detector, "channel_liquidity");
    assert_eq!(btcpay_finding.severity, rieko_findings::Severity::Critical);
    assert_eq!(
        btcpay_finding.provenance.as_ref().map(|p| &p.source),
        Some(&btcpay_source)
    );

    // 6. Generate deterministic recommendations across the unified graph
    let engine = RecommendationEngine;
    let recs = engine
        .recommend(btcpay_finding)
        .expect("recommendation generation succeeds");
    assert!(
        !recs.is_empty(),
        "recommendation engine should produce action candidates"
    );

    let rec = &recs[0];
    assert_eq!(rec.finding_id, btcpay_finding.id);
    assert_eq!(rec.action.target.as_deref(), Some("btcpay-chan-101"));
}
