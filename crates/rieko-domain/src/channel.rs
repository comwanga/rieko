use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{ChannelId, NodeId};

/// Lifecycle state of a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelStatus {
    Opening,
    Active,
    Inactive,
    Closing,
    Closed,
    PendingOpen,
    WaitingClose,
    ForceClosing,
}

impl ChannelStatus {
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Opening | Self::PendingOpen
        )
    }

    pub fn is_closed(self) -> bool {
        matches!(
            self,
            Self::Closed | Self::Closing | Self::WaitingClose | Self::ForceClosing
        )
    }
}

/// Which side of the channel the operator's liquidity has eroded toward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiquidityImbalance {
    Balanced,
    /// Local balance is low: we cannot send (outbound capacity drained).
    OutboundDrained,
    /// Remote balance is low: we cannot receive (inbound capacity drained).
    InboundDrained,
    /// Either side below a critical floor.
    SeverelyDrained,
}

/// Derived, operationally meaningful view of a channel's liquidity.
/// Computed at normalization time (D4: semantics live in domain objects).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LiquidityProfile {
    /// local_balance / capacity, in `0.0..=1.0`.
    pub local_ratio: f64,
    pub local_balance_msat: u64,
    pub remote_balance_msat: u64,
    /// Ability to receive (remote balance).
    pub inbound_capacity_msat: u64,
    /// Ability to send (local balance).
    pub outbound_capacity_msat: u64,
    pub imbalance: LiquidityImbalance,
}

impl LiquidityProfile {
    pub fn compute(capacity_msat: u64, local_balance_msat: u64, remote_balance_msat: u64) -> Self {
        let local_ratio = if capacity_msat == 0 {
            0.0
        } else {
            local_balance_msat as f64 / capacity_msat as f64
        };
        let imbalance = match local_ratio {
            r if r < 0.03 => LiquidityImbalance::SeverelyDrained,
            r if r > 0.97 => LiquidityImbalance::SeverelyDrained,
            r if r < 0.10 => LiquidityImbalance::OutboundDrained,
            r if r > 0.90 => LiquidityImbalance::InboundDrained,
            _ => LiquidityImbalance::Balanced,
        };
        Self {
            local_ratio,
            local_balance_msat,
            remote_balance_msat,
            inbound_capacity_msat: remote_balance_msat,
            outbound_capacity_msat: local_balance_msat,
            imbalance,
        }
    }
}

/// Routing fee policy on one direction of a channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePolicy {
    pub base_fee_msat: u64,
    pub fee_rate_ppm: u64,
    pub min_htlc_msat: u64,
    pub max_htlc_msat: Option<u64>,
    pub cltv_delta: u32,
}

impl Default for FeePolicy {
    fn default() -> Self {
        Self {
            base_fee_msat: 1_000,
            fee_rate_ppm: 1,
            min_htlc_msat: 1,
            max_htlc_msat: None,
            cltv_delta: 40,
        }
    }
}

/// An operationally-meaningful channel. Protocol-agnostic: produced by
/// normalizers from LND, CLN, LDK, or Eclair source data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Channel {
    pub id: ChannelId,
    pub node: NodeId,
    pub peer: NodeId,
    pub capacity_msat: u64,
    pub fee_policy: FeePolicy,
    pub status: ChannelStatus,
    pub liquidity: LiquidityProfile,
    pub last_seen: DateTime<Utc>,
    pub opening_height: Option<u32>,
}

impl Channel {
    pub fn healthy(&self) -> bool {
        self.liquidity.imbalance == LiquidityImbalance::Balanced
    }
}
