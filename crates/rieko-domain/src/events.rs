use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::ChannelId;

/// A single forwarding event (a payment routed through this node).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardEvent {
    /// Unique per forward (e.g. LND forwarding id).
    pub id: String,
    pub channel_in: ChannelId,
    pub channel_out: ChannelId,
    pub amount_msat: u64,
    pub fee_msat: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentStatus {
    InFlight,
    Succeeded,
    Failed,
}

/// A payment send attempt (relevant for outbound liquidity pressure).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentEvent {
    pub id: String,
    pub payment_hash: String,
    pub amount_msat: u64,
    pub fee_msat: u64,
    pub status: PaymentStatus,
    pub timestamp: DateTime<Utc>,
}
