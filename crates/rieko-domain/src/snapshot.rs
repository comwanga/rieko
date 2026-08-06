use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Channel, ChannelId, ChannelStatus};

/// A point-in-time view of a channel's liquidity and state. Persisted over
/// cycles so the engine can reason about trends (drift, deterioration) and,
/// later, run what-if simulations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelSnapshot {
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
    pub fn from_channel(channel: &Channel, ts: DateTime<Utc>) -> Self {
        Self {
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
