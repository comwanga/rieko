use chrono::DateTime;
use rieko_domain::{BitcoinNetwork, ChannelSnapshot, ChannelStatus};
use rieko_findings::{
    channel_snapshot_state_digest, ActionType, ChannelSnapshotReference, FindingProvenance,
    ObservationReference, ObservationSource,
};
use rieko_simulation::model::{
    FindingDirection, LiquidityRedistributionModel, LiquidityRedistributionParameters,
    ProjectedState, SimulationConfidence, SimulationInput, SimulationModel,
};

fn ts() -> DateTime<chrono::Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

fn snap(id: &str, local: u64, remote: u64, status: ChannelStatus) -> ChannelSnapshot {
    let capacity = local + remote;
    let mut s = ChannelSnapshot {
        node_id: Some("node-1".into()),
        network: Some(BitcoinNetwork::Regtest),
        state_digest: None,
        channel_id: id.into(),
        local_ratio: if capacity > 0 {
            local as f64 / capacity as f64
        } else {
            0.0
        },
        local_balance_msat: local,
        remote_balance_msat: remote,
        capacity_msat: capacity,
        status,
        ts: ts(),
        spendable_outbound_msat: local.saturating_sub(10_000),
        spendable_inbound_msat: remote.saturating_sub(10_000),
    };
    s.state_digest = Some(channel_snapshot_state_digest(&s));
    s
}

fn active(id: &str, local: u64, remote: u64) -> ChannelSnapshot {
    snap(id, local, remote, ChannelStatus::Active)
}

fn with_net(s: &mut ChannelSnapshot, net: BitcoinNetwork) {
    s.network = Some(net);
    s.state_digest = Some(channel_snapshot_state_digest(s));
}

fn provenance(net: Option<BitcoinNetwork>, channel: &str, digest: &str) -> FindingProvenance {
    FindingProvenance {
        network: net,
        source: ObservationSource::Fixture {
            redacted_hash: "hash".into(),
            configured_node: "node-1".into(),
        },
        producers: Vec::new(),
        observation: ObservationReference::ChannelState {
            channel_id: channel.into(),
            snapshot: ChannelSnapshotReference {
                network: net,
                observed_at: ts(),
                state_digest: digest.into(),
            },
        },
    }
}

fn make_input(
    finding_channel: &str,
    dir: FindingDirection,
    source: &ChannelSnapshot,
    dest: &ChannelSnapshot,
    amount: u64,
    net: Option<BitcoinNetwork>,
) -> SimulationInput {
    let finding_snap = if dir == FindingDirection::Inbound {
        source
    } else {
        dest
    };
    let digest = finding_snap
        .state_digest
        .clone()
        .unwrap_or_else(|| channel_snapshot_state_digest(finding_snap));
    SimulationInput {
        recommendation_id: "rec1".into(),
        recommendation_target: finding_channel.into(),
        finding_id: "f1".into(),
        finding_channel: finding_channel.into(),
        finding_direction: Some(dir),
        node_id: "node-1".into(),
        network: net,
        provenance: provenance(net, finding_channel, &digest),
        action_type: ActionType::RebalanceChannel,
        model_id: "liquidity-redistribution".into(),
        model_version: "3".into(),
        parameters: LiquidityRedistributionParameters {
            source_channel: source.channel_id.clone(),
            destination_channel: dest.channel_id.clone(),
            amount_msat: amount,
        },
        source_snapshot: source.clone(),
        destination_snapshot: dest.clone(),
    }
}

fn model() -> LiquidityRedistributionModel {
    LiquidityRedistributionModel::new()
}

fn pstate(local: u64, remote: u64, cap: u64) -> ProjectedState {
    ProjectedState {
        local_ratio: if cap > 0 {
            local as f64 / cap as f64
        } else {
            0.0
        },
        local_balance_msat: local,
        remote_balance_msat: remote,
        capacity_msat: cap,
    }
}

// Helper: at 1M capacity, 950K/50K = 0.95 ratio = inbound-drained.
// 50K/950K = 0.05 ratio = outbound-drained.

#[test]
fn balanced_channels_reject_wrong_direction() {
    let src = active("c1", 500_000, 500_000);
    let dst = active("c2", 500_000, 500_000);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        100_000,
        Some(BitcoinNetwork::Regtest),
    );
    assert!(model().simulate(&inp).is_err());
}

#[test]
fn outbound_heavy_channel() {
    let src = active("c2", 950_000, 50_000);
    let dst = active("c1", 50_000, 950_000); // outbound-drained
    let inp = make_input(
        "c1",
        FindingDirection::Outbound,
        &src,
        &dst,
        40_000,
        Some(BitcoinNetwork::Regtest),
    );
    let r = model().simulate(&inp).unwrap();
    assert_eq!(r.baseline, pstate(50_000, 950_000, 1_000_000));
    assert_eq!(r.projected, pstate(90_000, 910_000, 1_000_000));
    assert_eq!(r.confidence, SimulationConfidence::Medium);
}

#[test]
fn inbound_heavy_channel() {
    let src = active("c1", 950_000, 50_000); // inbound-drained
    let dst = active("c2", 200_000, 800_000);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        100_000,
        Some(BitcoinNetwork::Regtest),
    );
    let r = model().simulate(&inp).unwrap();
    assert_eq!(r.baseline, pstate(950_000, 50_000, 1_000_000));
    assert_eq!(r.projected, pstate(850_000, 150_000, 1_000_000));
}

#[test]
fn small_channel() {
    let src = active("c1", 95_000, 5_000); // inbound-drained, 95% local
    let dst = active("c2", 40_000, 60_000);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        10_000,
        Some(BitcoinNetwork::Regtest),
    );
    let r = model().simulate(&inp).unwrap();
    assert_eq!(r.projected.local_balance_msat, 85_000);
    assert!(r.projected.local_ratio > 0.8);
}

#[test]
fn large_channel() {
    let cap = 16_777_215_000u64;
    let local = (cap as f64 * 0.95) as u64; // ~95% → inbound-drained
    let remote = cap - local;
    let src = active("c1", local, remote);
    let dst = active("c2", remote, local);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        1_000_000_000,
        Some(BitcoinNetwork::Regtest),
    );
    let r = model().simulate(&inp).unwrap();
    assert_eq!(r.baseline.local_balance_msat, local);
    assert_eq!(
        r.projected.local_balance_msat,
        local.saturating_sub(1_000_000_000)
    );
}

#[test]
fn zero_capacity_rejected() {
    let src = active("c1", 0, 0);
    let dst = active("c2", 0, 0);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        100,
        Some(BitcoinNetwork::Regtest),
    );
    assert!(model().simulate(&inp).is_err());
}

#[test]
fn closed_channel_rejected() {
    let src = active("c1", 950_000, 50_000);
    let dst = snap("c2", 200_000, 800_000, ChannelStatus::Closed);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        100_000,
        Some(BitcoinNetwork::Regtest),
    );
    assert!(model().simulate(&inp).is_err());
}

#[test]
fn spendable_zero_enforced() {
    let mut src = active("c1", 950_000, 50_000);
    src.spendable_outbound_msat = 0;
    src.state_digest = Some(channel_snapshot_state_digest(&src));
    let dst = active("c2", 200_000, 800_000);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        100_000,
        Some(BitcoinNetwork::Regtest),
    );
    assert!(model().simulate(&inp).is_err());
}

#[test]
fn mainnet_path() {
    let mut src = active("c1", 950_000, 50_000);
    with_net(&mut src, BitcoinNetwork::Mainnet);
    let mut dst = active("c2", 200_000, 800_000);
    with_net(&mut dst, BitcoinNetwork::Mainnet);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        100_000,
        Some(BitcoinNetwork::Mainnet),
    );
    assert_eq!(
        model().simulate(&inp).unwrap().confidence,
        SimulationConfidence::Medium
    );
}

#[test]
fn testnet_path() {
    let mut src = active("c1", 950_000, 50_000);
    with_net(&mut src, BitcoinNetwork::Testnet);
    let mut dst = active("c2", 200_000, 800_000);
    with_net(&mut dst, BitcoinNetwork::Testnet);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        100_000,
        Some(BitcoinNetwork::Testnet),
    );
    assert_eq!(
        model().simulate(&inp).unwrap().confidence,
        SimulationConfidence::Medium
    );
}

#[test]
fn delta_projections_match_manual_calculation() {
    let src = active("c1", 950_000, 50_000);
    let dst = active("c2", 200_000, 800_000);
    let amt = 150_000;
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        amt,
        Some(BitcoinNetwork::Regtest),
    );
    let r = model().simulate(&inp).unwrap();
    assert_eq!(r.deltas[0].local_after_msat, 950_000 - amt);
    assert_eq!(r.deltas[0].remote_after_msat, 50_000 + amt);
    assert_eq!(r.deltas[1].local_after_msat, 200_000 + amt);
    assert_eq!(r.deltas[1].remote_after_msat, 800_000 - amt);
}

#[test]
fn baseline_matches_finding_channel_snapshot() {
    let src = active("c1", 950_000, 50_000);
    let dst = active("c2", 200_000, 800_000);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        50_000,
        Some(BitcoinNetwork::Regtest),
    );
    let r = model().simulate(&inp).unwrap();
    assert_eq!(r.baseline.local_balance_msat, src.local_balance_msat);
    assert_eq!(r.baseline.capacity_msat, src.capacity_msat);
}

#[test]
fn warnings_fire_for_large_amount_and_reserve() {
    let cap = 1_000_000;
    let src = active("c1", cap - 50_000, 50_000); // 0.95 ratio inbound
    let dst = active("c2", 50_000, cap - 50_000);
    let amt = 800_000;
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        amt,
        Some(BitcoinNetwork::Regtest),
    );
    let r = model().simulate(&inp).unwrap();
    assert!(r
        .warnings
        .iter()
        .any(|w| w.code == "amount_exceeds_half_capacity"));
}

#[test]
fn source_balance_near_reserve_warning() {
    let cap = 3_000_000;
    let src_local = cap - 150_000;
    let src = active("c1", src_local, 150_000);
    let amt = src_local - 15_000; // leaves 15K after, below 30K reserve
    let dst = active("c2", 100_000, cap - 100_000);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        amt,
        Some(BitcoinNetwork::Regtest),
    );
    let r = model().simulate(&inp).unwrap();
    assert!(r
        .warnings
        .iter()
        .any(|w| w.code == "source_balance_near_reserve"));
}

#[test]
fn no_warnings_on_modest_rebalance() {
    let src = active("c1", 950_000, 50_000);
    let dst = active("c2", 400_000, 600_000);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        200_000,
        Some(BitcoinNetwork::Regtest),
    );
    let r = model().simulate(&inp).unwrap();
    assert!(r.warnings.is_empty());
}

#[test]
fn same_input_produces_identical_hashes_and_projections() {
    let src = active("c1", 950_000, 50_000);
    let dst = active("c2", 200_000, 800_000);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        50_000,
        Some(BitcoinNetwork::Regtest),
    );
    let r1 = model().simulate(&inp).unwrap();
    let r2 = model().simulate(&inp).unwrap();
    assert_eq!(r1.input_hash, r2.input_hash);
    assert_eq!(r1.baseline, r2.baseline);
}

#[test]
fn assumptions_have_stable_codes() {
    let src = active("c1", 950_000, 50_000);
    let dst = active("c2", 200_000, 800_000);
    let inp = make_input(
        "c1",
        FindingDirection::Inbound,
        &src,
        &dst,
        50_000,
        Some(BitcoinNetwork::Regtest),
    );
    let r = model().simulate(&inp).unwrap();
    let codes: Vec<&str> = r.assumptions.iter().map(|a| a.code.as_str()).collect();
    assert!(codes.contains(&"fees_not_estimated"));
    assert!(codes.contains(&"external_network_state_unmodelled"));
}
