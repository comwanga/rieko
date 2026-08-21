use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{BitcoinNetwork, Channel, ChannelId, ChannelStatus};

/// A point-in-time view of a channel's liquidity and state. Persisted over
/// cycles so the engine can reason about trends (drift, deterioration) and,
/// later, run what-if simulations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelSnapshot {
    /// Configured local node identity. Legacy rows may not have one.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Bitcoin chain for this observation. Legacy snapshots may not have one.
    #[serde(default)]
    pub network: Option<BitcoinNetwork>,
    /// Digest of this snapshot's state. Legacy snapshots may not have one.
    #[serde(default)]
    pub state_digest: Option<String>,
    pub channel_id: String,
    pub local_ratio: f64,
    pub local_balance_msat: u64,
    pub remote_balance_msat: u64,
    pub capacity_msat: u64,
    pub status: ChannelStatus,
    pub ts: DateTime<Utc>,
    /// Effective outbound after subtracting local reserve. Zero when unknown.
    #[serde(default)]
    pub spendable_outbound_msat: u64,
    /// Effective inbound after subtracting remote reserve.
    #[serde(default)]
    pub spendable_inbound_msat: u64,
}

impl ChannelSnapshot {
    pub fn from_channel(channel: &Channel, ts: DateTime<Utc>, network: BitcoinNetwork) -> Self {
        Self {
            node_id: Some(channel.node.to_string()),
            network: Some(network),
            state_digest: None,
            channel_id: channel.id.to_string(),
            local_ratio: channel.liquidity.local_ratio,
            local_balance_msat: channel.liquidity.local_balance_msat,
            remote_balance_msat: channel.liquidity.remote_balance_msat,
            capacity_msat: channel.capacity_msat,
            status: channel.status,
            ts,
            spendable_outbound_msat: channel.liquidity.spendable_outbound_msat,
            spendable_inbound_msat: channel.liquidity.spendable_inbound_msat,
        }
    }

    pub fn channel_id(&self) -> ChannelId {
        ChannelId::new(&self.channel_id)
    }
}

/// A point-in-time aggregate view of a node's operational and liquidity state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeSnapshot {
    /// Configured or discovered node identity.
    pub node_id: String,
    /// Bitcoin chain network.
    pub network: BitcoinNetwork,
    /// Timestamp when this snapshot was captured.
    pub captured_at: DateTime<Utc>,
    /// Observed channels at this point in time.
    pub channels: Vec<ChannelSnapshot>,
    /// Total aggregate local balance in millisatoshis across all active channels.
    pub total_local_balance_msat: u64,
    /// Total aggregate remote balance in millisatoshis across all active channels.
    pub total_remote_balance_msat: u64,
    /// Total aggregate capacity in millisatoshis across all channels.
    pub total_capacity_msat: u64,
    /// Count of active channels.
    pub active_channels_count: u32,
    /// Count of inactive channels.
    pub inactive_channels_count: u32,
    /// Count of pending/opening/closing channels.
    pub pending_channels_count: u32,
    /// Bitcoin block height reported by the node or backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u32>,
    /// On-chain confirmed balance in satoshis if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onchain_balance_sats: Option<u64>,
    /// Digest of the snapshot state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_digest: Option<String>,
}

impl NodeSnapshot {
    pub fn from_channels(
        node_id: impl Into<String>,
        network: BitcoinNetwork,
        channels: Vec<ChannelSnapshot>,
        captured_at: DateTime<Utc>,
        block_height: Option<u32>,
        onchain_balance_sats: Option<u64>,
    ) -> Self {
        let mut total_local = 0u64;
        let mut total_remote = 0u64;
        let mut total_capacity = 0u64;
        let mut active_count = 0u32;
        let mut inactive_count = 0u32;
        let mut pending_count = 0u32;

        for c in &channels {
            total_capacity = total_capacity.saturating_add(c.capacity_msat);
            match c.status {
                ChannelStatus::Active => {
                    active_count = active_count.saturating_add(1);
                    total_local = total_local.saturating_add(c.local_balance_msat);
                    total_remote = total_remote.saturating_add(c.remote_balance_msat);
                }
                ChannelStatus::Inactive => {
                    inactive_count = inactive_count.saturating_add(1);
                }
                ChannelStatus::Opening
                | ChannelStatus::Closing
                | ChannelStatus::PendingOpen
                | ChannelStatus::WaitingClose
                | ChannelStatus::ForceClosing => {
                    pending_count = pending_count.saturating_add(1);
                }
                ChannelStatus::Closed | ChannelStatus::Unknown => {}
            }
        }

        Self {
            node_id: node_id.into(),
            network,
            captured_at,
            channels,
            total_local_balance_msat: total_local,
            total_remote_balance_msat: total_remote,
            total_capacity_msat: total_capacity,
            active_channels_count: active_count,
            inactive_channels_count: inactive_count,
            pending_channels_count: pending_count,
            block_height,
            onchain_balance_sats,
            state_digest: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_snapshot_deserializes_without_network_or_digest() {
        let snapshot: ChannelSnapshot = serde_json::from_value(serde_json::json!({
            "node_id": "local-node",
            "channel_id": "c1",
            "local_ratio": 0.5,
            "local_balance_msat": 50,
            "remote_balance_msat": 50,
            "capacity_msat": 100,
            "status": "Active",
            "ts": "2026-08-10T00:00:00Z"
        }))
        .unwrap();

        assert_eq!(snapshot.network, None);
        assert_eq!(snapshot.state_digest, None);
    }

    #[test]
    fn aggregates_node_snapshot_metrics() {
        let now = Utc::now();
        let c1 = ChannelSnapshot {
            node_id: Some("node-1".into()),
            network: Some(BitcoinNetwork::Mainnet),
            state_digest: None,
            channel_id: "chan-1".into(),
            local_ratio: 0.75,
            local_balance_msat: 75_000,
            remote_balance_msat: 25_000,
            capacity_msat: 100_000,
            status: ChannelStatus::Active,
            ts: now,
            spendable_outbound_msat: 70_000,
            spendable_inbound_msat: 20_000,
        };
        let c2 = ChannelSnapshot {
            node_id: Some("node-1".into()),
            network: Some(BitcoinNetwork::Mainnet),
            state_digest: None,
            channel_id: "chan-2".into(),
            local_ratio: 0.0,
            local_balance_msat: 0,
            remote_balance_msat: 50_000,
            capacity_msat: 50_000,
            status: ChannelStatus::Inactive,
            ts: now,
            spendable_outbound_msat: 0,
            spendable_inbound_msat: 45_000,
        };

        let node_snap = NodeSnapshot::from_channels(
            "node-1",
            BitcoinNetwork::Mainnet,
            vec![c1, c2],
            now,
            Some(850000),
            Some(1_000_000),
        );

        assert_eq!(node_snap.active_channels_count, 1);
        assert_eq!(node_snap.inactive_channels_count, 1);
        assert_eq!(node_snap.total_local_balance_msat, 75_000);
        assert_eq!(node_snap.total_remote_balance_msat, 25_000);
        assert_eq!(node_snap.total_capacity_msat, 150_000);
        assert_eq!(node_snap.block_height, Some(850000));
        assert_eq!(node_snap.onchain_balance_sats, Some(1_000_000));
    }
}
