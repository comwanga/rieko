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
}
