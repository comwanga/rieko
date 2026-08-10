use sha2::{Digest, Sha256};

use rieko_domain::{BitcoinNetwork, Channel, ChannelSnapshot, ChannelStatus, LiquidityImbalance};

use crate::{ActionType, Evidence};

/// Stable, deterministic identity for operational observations.
///
/// Guarantees that replaying the same observation produces the same identity
/// across process runs (RIEKO-AUDIT-002), so persistence can deduplicate on a
/// stable key rather than a fresh random UUID. LLM explanations, wall-clock
/// timestamps, and anything that would change merely because data was processed
/// again are deliberately excluded.
///
/// See [`finding_identity`] and [`action_identity`] for the documented inputs.
fn digest(f: impl FnOnce(&mut Sha256)) -> String {
    let mut hasher = Sha256::new();
    f(&mut hasher);
    format!("{:x}", hasher.finalize())
}

fn field(hasher: &mut Sha256, bytes: impl AsRef<[u8]>) {
    let bytes = bytes.as_ref();
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn optional_field(hasher: &mut Sha256, value: Option<impl AsRef<[u8]>>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            field(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn status_tag(status: ChannelStatus) -> u8 {
    match status {
        ChannelStatus::Opening => 0,
        ChannelStatus::Active => 1,
        ChannelStatus::Inactive => 2,
        ChannelStatus::Closing => 3,
        ChannelStatus::Closed => 4,
        ChannelStatus::PendingOpen => 5,
        ChannelStatus::WaitingClose => 6,
        ChannelStatus::ForceClosing => 7,
        ChannelStatus::Unknown => 8,
    }
}

fn imbalance_tag(imbalance: LiquidityImbalance) -> u8 {
    match imbalance {
        LiquidityImbalance::Balanced => 0,
        LiquidityImbalance::OutboundDrained => 1,
        LiquidityImbalance::InboundDrained => 2,
        LiquidityImbalance::SeverelyDrained => 3,
        LiquidityImbalance::Unknown => 4,
    }
}

/// Stable identity for a finding.
///
/// Inputs (all deterministic for a fixed logical occurrence):
/// * detector identifier (`detector`)
/// * detector version
/// * entity: local node id + channel id
///
/// Severity and evidence are current condition attributes, not logical
/// identity inputs.
pub fn finding_identity(
    detector: &str,
    detector_version: &str,
    network: Option<BitcoinNetwork>,
    node: Option<&str>,
    channel: Option<&str>,
) -> String {
    let key = digest(|m| {
        field(m, b"rieko-finding-v2");
        field(m, detector);
        field(m, detector_version);
        optional_field(m, network.map(|network| network.to_string()));
        optional_field(m, node);
        optional_field(m, channel);
    });
    format!("finding-{key}")
}

/// SHA-256 digest of explicit operational channel state.
///
/// `last_seen` is intentionally excluded: it says when the state was observed,
/// not what state was observed.
pub fn channel_state_digest(channel: &Channel) -> String {
    digest(|m| {
        field(m, b"rieko-channel-state-v1");
        field(m, channel.id.as_str());
        field(m, channel.node.as_str());
        field(m, channel.peer.as_str());
        field(m, &channel.channel_point);
        field(m, channel.capacity_msat.to_be_bytes());
        field(m, channel.fee_policy.base_fee_msat.to_be_bytes());
        field(m, channel.fee_policy.fee_rate_ppm.to_be_bytes());
        field(m, channel.fee_policy.min_htlc_msat.to_be_bytes());
        optional_field(m, channel.fee_policy.max_htlc_msat.map(u64::to_be_bytes));
        field(m, channel.fee_policy.cltv_delta.to_be_bytes());
        field(m, [status_tag(channel.status)]);
        field(m, channel.liquidity.local_ratio.to_bits().to_be_bytes());
        field(m, channel.liquidity.local_balance_msat.to_be_bytes());
        field(m, channel.liquidity.remote_balance_msat.to_be_bytes());
        field(m, channel.liquidity.inbound_capacity_msat.to_be_bytes());
        field(m, channel.liquidity.outbound_capacity_msat.to_be_bytes());
        field(m, channel.liquidity.spendable_outbound_msat.to_be_bytes());
        field(m, channel.liquidity.spendable_inbound_msat.to_be_bytes());
        field(m, [imbalance_tag(channel.liquidity.imbalance)]);
        optional_field(m, channel.opening_height.map(u32::to_be_bytes));
        optional_field(m, channel.local_reserve_msat.map(u64::to_be_bytes));
        optional_field(m, channel.remote_reserve_msat.map(u64::to_be_bytes));
        field(m, [u8::from(channel.is_private)]);
        field(m, [u8::from(channel.is_initiator)]);
        optional_field(m, channel.total_sent_msat.map(u64::to_be_bytes));
        optional_field(m, channel.total_received_msat.map(u64::to_be_bytes));
    })
}

/// SHA-256 digest of explicit snapshot state, excluding its observation time.
pub fn channel_snapshot_state_digest(snapshot: &ChannelSnapshot) -> String {
    digest(|m| {
        field(m, b"rieko-channel-snapshot-state-v3");
        optional_field(m, snapshot.node_id.as_deref());
        optional_field(m, snapshot.network.map(|network| network.to_string()));
        field(m, &snapshot.channel_id);
        field(m, snapshot.local_ratio.to_bits().to_be_bytes());
        field(m, snapshot.local_balance_msat.to_be_bytes());
        field(m, snapshot.remote_balance_msat.to_be_bytes());
        field(m, snapshot.capacity_msat.to_be_bytes());
        field(m, [status_tag(snapshot.status)]);
        field(m, snapshot.spendable_outbound_msat.to_be_bytes());
        field(m, snapshot.spendable_inbound_msat.to_be_bytes());
    })
}

/// Stable identity for an action, derived from its source finding and action
/// kind + target — never a fresh random id alone (RIEKO-AUDIT-002).
pub fn action_identity(finding_id: &str, action_type: ActionType, target: Option<&str>) -> String {
    let key = digest(|m| {
        m.update(b"rieko-action-v1");
        m.update([0u8]);
        m.update(finding_id.as_bytes());
        m.update([0u8]);
        m.update(action_type.as_str().as_bytes());
        m.update([0u8]);
        m.update(target.unwrap_or_default().as_bytes());
    });
    format!("action-{key}")
}

/// Canonical, order-independent byte encoding of an evidence list.
///
/// Retained for consumers that need an evidence digest; finding identity does
/// not include evidence.
pub fn canonical_evidence(evidence: &[Evidence]) -> Vec<u8> {
    let mut sorted: Vec<&Evidence> = evidence.iter().collect();
    sorted.sort_by(|a, b| a.key.cmp(&b.key));
    let mut out = Vec::new();
    for e in sorted {
        out.extend_from_slice(e.key.as_bytes());
        out.push(0u8);
        match &e.value {
            serde_json::Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
            serde_json::Value::String(s) => out.extend_from_slice(s.as_bytes()),
            serde_json::Value::Bool(b) => out.push(if *b { 1 } else { 0 }),
            other => {
                out.extend_from_slice(serde_json::to_vec(other).unwrap_or_default().as_slice())
            }
        }
        out.push(0xFF);
    }
    out
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use rieko_domain::{ChannelId, FeePolicy, LiquidityProfile, NodeId};

    use super::*;

    fn channel(last_seen: chrono::DateTime<Utc>) -> Channel {
        Channel {
            id: ChannelId::new("c1"),
            node: NodeId::new("node1"),
            peer: NodeId::new("peer1"),
            channel_point: "txid:0".into(),
            capacity_msat: 1_000_000,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity: LiquidityProfile::compute(1_000_000, 200_000, 800_000),
            last_seen,
            opening_height: Some(800_000),
            local_reserve_msat: Some(10_000),
            remote_reserve_msat: Some(20_000),
            is_private: false,
            is_initiator: true,
            total_sent_msat: Some(50_000),
            total_received_msat: Some(60_000),
        }
    }

    #[test]
    fn identity_stable_across_construction() {
        let a = finding_identity(
            "channel_liquidity",
            "1",
            None,
            Some("node1"),
            Some("chan-abc"),
        );
        let b = finding_identity(
            "channel_liquidity",
            "1",
            None,
            Some("node1"),
            Some("chan-abc"),
        );
        assert_eq!(a, b);
        assert!(a.starts_with("finding-"));
    }

    #[test]
    fn identity_distinguishes_detector_version() {
        // Same detector + input, but a new detector version, must be
        // distinguishable (WP2.3: changed detector version is distinguishable).
        let v1 = finding_identity("channel_liquidity", "1", None, Some("node1"), Some("c1"));
        let v2 = finding_identity("channel_liquidity", "2", None, Some("node1"), Some("c1"));
        assert_ne!(v1, v2);
    }

    #[test]
    fn identity_distinguishes_entity_changes() {
        let a = finding_identity("channel_liquidity", "1", None, Some("node1"), Some("c1"));
        let b = finding_identity("channel_liquidity", "1", None, Some("node1"), Some("c2"));
        let c = finding_identity("channel_liquidity", "1", None, Some("node2"), Some("c1"));
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn identity_distinguishes_networks() {
        let mainnet = finding_identity(
            "channel_liquidity",
            "1",
            Some(BitcoinNetwork::Mainnet),
            Some("node1"),
            Some("c1"),
        );
        let regtest = finding_identity(
            "channel_liquidity",
            "1",
            Some(BitcoinNetwork::Regtest),
            Some("node1"),
            Some("c1"),
        );
        assert_ne!(mainnet, regtest);
    }

    #[test]
    fn identity_distinguishes_absent_and_empty_entity_parts() {
        assert_ne!(
            finding_identity("detector", "1", None, None, Some("c1")),
            finding_identity("detector", "1", None, Some(""), Some("c1"))
        );
    }

    #[test]
    fn channel_digest_excludes_observation_timestamp() {
        let first = channel(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let later = Channel {
            last_seen: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            ..first.clone()
        };

        assert_eq!(channel_state_digest(&first), channel_state_digest(&later));
    }

    #[test]
    fn channel_digest_changes_with_explicit_state() {
        let original = channel(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let changed = Channel {
            capacity_msat: original.capacity_msat + 1,
            ..original.clone()
        };

        assert_ne!(
            channel_state_digest(&original),
            channel_state_digest(&changed)
        );
        assert_eq!(channel_state_digest(&original).len(), 64);
    }

    #[test]
    fn snapshot_digest_excludes_observation_timestamp_but_includes_state() {
        let channel = channel(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let original = ChannelSnapshot::from_channel(
            &channel,
            channel.last_seen,
            rieko_domain::BitcoinNetwork::Signet,
        );
        let later = ChannelSnapshot {
            ts: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            ..original.clone()
        };
        let changed = ChannelSnapshot {
            local_balance_msat: original.local_balance_msat + 1,
            ..original.clone()
        };

        assert_eq!(
            channel_snapshot_state_digest(&original),
            channel_snapshot_state_digest(&later)
        );
        assert_ne!(
            channel_snapshot_state_digest(&original),
            channel_snapshot_state_digest(&changed)
        );
        let different_network = ChannelSnapshot {
            network: Some(rieko_domain::BitcoinNetwork::Regtest),
            ..original.clone()
        };
        assert_ne!(
            channel_snapshot_state_digest(&original),
            channel_snapshot_state_digest(&different_network)
        );
        let digest_field_changed = ChannelSnapshot {
            state_digest: Some("stored-digest".into()),
            ..original.clone()
        };
        assert_eq!(
            channel_snapshot_state_digest(&original),
            channel_snapshot_state_digest(&digest_field_changed)
        );
    }

    #[test]
    fn action_identity_derives_from_finding_and_kind() {
        let a = action_identity("finding-x", ActionType::RebalanceChannel, Some("c1"));
        let b = action_identity("finding-x", ActionType::RebalanceChannel, Some("c1"));
        let c = action_identity("finding-x", ActionType::UpdateFeePolicy, Some("c1"));
        let d = action_identity("finding-y", ActionType::RebalanceChannel, Some("c1"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert!(a.starts_with("action-"));
    }
}
