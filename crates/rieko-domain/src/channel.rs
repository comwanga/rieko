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
    /// The source reported a state or flag combination we do not understand, or
    /// the state data was malformed. Deliberately distinct from `Active`:
    /// unknown data is never assumed healthy (RIEKO-AUDIT-021).
    Unknown,
}

impl ChannelStatus {
    pub fn is_open(self) -> bool {
        matches!(self, Self::Active | Self::Opening | Self::PendingOpen)
    }

    pub fn is_closed(self) -> bool {
        matches!(
            self,
            Self::Closed | Self::Closing | Self::WaitingClose | Self::ForceClosing
        )
    }
}

/// Which side of the channel the operator's liquidity has eroded toward.
///
/// This is a *structural condition*, not a directive: an imbalance is a risk
/// signal, never proof that rebalancing is required (RIEKO-AUDIT-011).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiquidityImbalance {
    /// Liquidity is broadly even between the two sides.
    Balanced,
    /// Local balance is low: we cannot send (outbound capacity drained).
    OutboundDrained,
    /// Remote balance is low: we cannot receive (inbound capacity drained).
    InboundDrained,
    /// Either side below a critical floor.
    SeverelyDrained,
    /// The channel's liquidity cannot be classified: zero capacity, a balance
    /// exceeding capacity, or missing balance data. Never treated as healthy
    /// *or* drained.
    Unknown,
}

/// Derived, operationally meaningful view of a channel's liquidity.
/// Computed at normalization time (D4: semantics live in domain objects).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LiquidityProfile {
    /// `local_balance / capacity`, normally in `0.0..=1.0`. May be `0.0` for a
    /// zero-capacity channel or exceed `1.0` when a balance exceeds capacity;
    /// such profiles carry [`LiquidityImbalance::Unknown`] and are never
    /// classified as healthy or drained.
    pub local_ratio: f64,
    pub local_balance_msat: u64,
    pub remote_balance_msat: u64,
    /// Ability to receive (remote balance).
    pub inbound_capacity_msat: u64,
    /// Ability to send (local balance).
    pub outbound_capacity_msat: u64,
    /// Effective outbound capacity after subtracting `local_chan_reserve`.
    /// Zero when reserves are unknown (the v1 default).
    pub spendable_outbound_msat: u64,
    /// Effective inbound capacity after subtracting `remote_chan_reserve`.
    pub spendable_inbound_msat: u64,
    pub imbalance: LiquidityImbalance,
}

impl LiquidityProfile {
    /// v1 classification thresholds (RIEKO-AUDIT-011). These are documented
    /// heuristics, not universal truth:
    ///
    /// * `0.03` — outbound floor below which the channel is
    ///   `SeverelyDrained`; mirrored at `0.97` for inbound. Unit: fraction of
    ///   capacity (`0.0..=1.0`). Boundary: strictly below `0.03` (strictly
    ///   above `0.97`). Configuration status: fixed for v1, not operator
    ///   tunable.
    /// * `0.10` — outbound floor below which the channel is
    ///   `OutboundDrained`; mirrored at `0.90` for inbound. Boundary: the
    ///   `0.03..0.10` band is `OutboundDrained`; `0.90..0.97` is
    ///   `InboundDrained`. A ratio exactly at `0.10`/`0.90` is `Balanced`.
    ///
    /// Invalid input never produces a liquidity class: zero capacity, or a
    /// balance exceeding capacity, yields [`LiquidityImbalance::Unknown`].
    /// Negative balances are rejected earlier at ingestion
    /// (`NormalizerError::NegativeBalance`).
    pub fn compute(capacity_msat: u64, local_balance_msat: u64, remote_balance_msat: u64) -> Self {
        if capacity_msat == 0
            || local_balance_msat > capacity_msat
            || remote_balance_msat > capacity_msat
        {
            return Self {
                local_ratio: if capacity_msat == 0 {
                    0.0
                } else {
                    local_balance_msat as f64 / capacity_msat as f64
                },
                local_balance_msat,
                remote_balance_msat,
                inbound_capacity_msat: remote_balance_msat,
                outbound_capacity_msat: local_balance_msat,
                spendable_outbound_msat: 0,
                spendable_inbound_msat: 0,
                imbalance: LiquidityImbalance::Unknown,
            };
        }
        let local_ratio = local_balance_msat as f64 / capacity_msat as f64;
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
            spendable_outbound_msat: 0,
            spendable_inbound_msat: 0,
            imbalance,
        }
    }

    /// A profile whose balance data is absent or unclassifiable. Distinct from
    /// `Balanced`: missing data is not proof of health.
    pub fn unknown() -> Self {
        Self {
            local_ratio: 0.0,
            local_balance_msat: 0,
            remote_balance_msat: 0,
            inbound_capacity_msat: 0,
            outbound_capacity_msat: 0,
            spendable_outbound_msat: 0,
            spendable_inbound_msat: 0,
            imbalance: LiquidityImbalance::Unknown,
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
    /// Funding transaction outpoint (`txid:index`). Required for per-channel
    /// fee policy targeting (RIEKO-AUDIT-011).
    pub channel_point: String,
    pub capacity_msat: u64,
    pub fee_policy: FeePolicy,
    pub status: ChannelStatus,
    pub liquidity: LiquidityProfile,
    pub last_seen: DateTime<Utc>,
    pub opening_height: Option<u32>,
    /// Local channel reserve in msat. The operator cannot spend below this
    /// floor, so effective outbound is `local_balance - local_reserve`.
    #[serde(default)]
    pub local_reserve_msat: Option<u64>,
    /// Remote channel reserve in msat.
    #[serde(default)]
    pub remote_reserve_msat: Option<u64>,
    /// Whether this is an unannounced (private) channel. Private channels
    /// have no forwarding demand, so imbalance is less concerning.
    #[serde(default)]
    pub is_private: bool,
    /// Whether the local node opened this channel. Affects force-close risk:
    /// the initiator cannot close without partner cooperation in some cases.
    #[serde(default)]
    pub is_initiator: bool,
    /// Lifetime outbound volume in msat. Used to detect channel role (source,
    /// sink, or transit) from actual behaviour rather than assumptions.
    #[serde(default)]
    pub total_sent_msat: Option<u64>,
    /// Lifetime inbound volume in msat.
    #[serde(default)]
    pub total_received_msat: Option<u64>,
}

impl Channel {
    pub fn healthy(&self) -> bool {
        self.liquidity.imbalance == LiquidityImbalance::Balanced
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_is_unknown_not_drained() {
        let p = LiquidityProfile::compute(0, 0, 0);
        assert_eq!(p.imbalance, LiquidityImbalance::Unknown);
        assert_eq!(p.local_ratio, 0.0);
    }

    #[test]
    fn balance_exceeding_capacity_is_unknown_not_a_liquidity_class() {
        // local > capacity must never decode as InboundDrained (RIEKO-AUDIT-011).
        let p = LiquidityProfile::compute(100, 120, 0);
        assert_eq!(p.imbalance, LiquidityImbalance::Unknown);
        assert!(p.local_ratio > 1.0);
        let p2 = LiquidityProfile::compute(100, 0, 120);
        assert_eq!(p2.imbalance, LiquidityImbalance::Unknown);
    }

    #[test]
    fn unknown_is_distinct_from_balanced() {
        assert_ne!(
            LiquidityProfile::unknown().imbalance,
            LiquidityImbalance::Balanced
        );
        assert!(!LiquidityProfile::unknown()
            .imbalance
            .eq(&LiquidityImbalance::Balanced));
    }

    #[test]
    fn drain_classification_boundaries() {
        // Strict lower bounds: exactly 0.03 and 0.10 are NOT Severely/OutboundDrained.
        assert_eq!(
            LiquidityProfile::compute(100_000, 3_000, 97_000).imbalance,
            LiquidityImbalance::OutboundDrained
        );
        assert_eq!(
            LiquidityProfile::compute(100_000, 2_999, 97_001).imbalance,
            LiquidityImbalance::SeverelyDrained
        );
        // Exactly 0.10 is Balanced (drain floor is strict).
        assert_eq!(
            LiquidityProfile::compute(100_000, 10_000, 90_000).imbalance,
            LiquidityImbalance::Balanced
        );
        assert_eq!(
            LiquidityProfile::compute(100_000, 9_999, 90_001).imbalance,
            LiquidityImbalance::OutboundDrained
        );
        // Mirrored inbound band.
        assert_eq!(
            LiquidityProfile::compute(100_000, 95_000, 5_000).imbalance,
            LiquidityImbalance::InboundDrained
        );
        assert_eq!(
            LiquidityProfile::compute(100_000, 98_000, 2_000).imbalance,
            LiquidityImbalance::SeverelyDrained
        );
    }

    #[test]
    fn balanced_band_is_silent_and_healthy() {
        let c = Channel {
            id: ChannelId::new("c1"),
            node: NodeId::new("n"),
            peer: NodeId::new("p"),
            channel_point: "txn:0".into(),
            capacity_msat: 100_000,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity: LiquidityProfile::compute(100_000, 50_000, 50_000),
            last_seen: Utc::now(),
            opening_height: Some(1),
            local_reserve_msat: None,
            remote_reserve_msat: None,
            is_private: false,
            is_initiator: true,
            total_sent_msat: None,
            total_received_msat: None,
        };
        assert_eq!(c.liquidity.imbalance, LiquidityImbalance::Balanced);
        assert!(c.healthy());
        // Unknown is never "healthy" even though it is not drained.
        let c = Channel {
            liquidity: LiquidityProfile::unknown(),
            ..c
        };
        assert!(!c.healthy());
    }
}
