use chrono::{DateTime, Utc};
use rieko_domain::{
    Channel, ChannelId, ChannelStatus, FeePolicy, ForwardEvent, LiquidityProfile, NodeId,
};
use thiserror::Error;

use crate::model::{LndChannel, LndForward};

#[derive(Debug, Error)]
pub enum NormalizerError {
    #[error("malformed channel point `{0}`: expected txid:index")]
    BadChannelPoint(String),
    #[error("negative balance on channel {0}")]
    NegativeBalance(String),
}

/// Pure normalizers: LND wire types → domain objects (D4). No I/O here, so
/// the semantics are unit-testable with fixtures.
pub struct Normalizer;

impl Normalizer {
    pub fn channel(
        lnd: &LndChannel,
        local_node: &NodeId,
        seen_at: DateTime<Utc>,
    ) -> Result<Channel, NormalizerError> {
        let id = lnd.chan_point.replace(':', "x");
        if !lnd.chan_point.contains(':') {
            return Err(NormalizerError::BadChannelPoint(lnd.chan_point.clone()));
        }
        let capacity = u64::try_from(lnd.capacity).unwrap_or(0);
        let local = u64::try_from(lnd.local_balance)
            .map_err(|_| NormalizerError::NegativeBalance(id.clone()))?;
        let remote = u64::try_from(lnd.remote_balance)
            .map_err(|_| NormalizerError::NegativeBalance(id.clone()))?;

        Ok(Channel {
            id: ChannelId::new(id),
            node: local_node.clone(),
            peer: NodeId::new(lnd.remote_pubkey.clone()),
            capacity_msat: capacity * 1_000,
            fee_policy: FeePolicy::default(),
            status: status_from_flags(&lnd.chan_status_flags),
            liquidity: LiquidityProfile::compute(capacity * 1_000, local * 1_000, remote * 1_000),
            last_seen: seen_at,
            opening_height: None,
        })
    }

    pub fn forward(lnd: &LndForward) -> ForwardEvent {
        ForwardEvent {
            id: format!(
                "{}_{}_{}_{}",
                lnd.chan_id_in, lnd.chan_id_out, lnd.timestamp, lnd.fee_msat
            ),
            channel_in: ChannelId::new(lnd.chan_id_in.to_string()),
            channel_out: ChannelId::new(lnd.chan_id_out.to_string()),
            amount_msat: u64::try_from(lnd.amt_in_msat).unwrap_or(0),
            fee_msat: u64::try_from(lnd.fee_msat).unwrap_or(0),
            timestamp: Utc::now(),
        }
    }
}

fn status_from_flags(flags: &str) -> ChannelStatus {
    // LND chan_status_flags is a bitfield string; map the common cases.
    let num = flags.parse::<u32>().unwrap_or(0);
    if num == 0 {
        ChannelStatus::Active
    } else if num & 2 != 0 {
        ChannelStatus::ForceClosing
    } else if num & 4 != 0 {
        ChannelStatus::Inactive
    } else {
        ChannelStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_maps_balances_to_msat() {
        let lnd = LndChannel {
            chan_point: "abc123:1".into(),
            remote_pubkey: "peerpubkey".into(),
            capacity: 100_000,
            local_balance: 95_000,
            remote_balance: 5_000,
            commit_fee: 100,
            chan_status_flags: "0".into(),
        };
        let c = Normalizer::channel(&lnd, &NodeId::new("local"), Utc::now()).unwrap();
        assert_eq!(c.capacity_msat, 100_000_000);
        assert_eq!(c.liquidity.local_balance_msat, 95_000_000);
        assert_eq!(
            c.liquidity.imbalance,
            rieko_domain::LiquidityImbalance::InboundDrained
        );
        assert!(c.status.is_open());
        assert_eq!(c.peer.as_str(), "peerpubkey");
    }

    #[test]
    fn bad_channel_point_is_rejected() {
        let lnd = LndChannel {
            chan_point: "no-colon-here".into(),
            remote_pubkey: "p".into(),
            capacity: 100,
            local_balance: 90,
            remote_balance: 10,
            commit_fee: 0,
            chan_status_flags: "0".into(),
        };
        assert!(Normalizer::channel(&lnd, &NodeId::new("local"), Utc::now()).is_err());
    }
}
