use std::collections::{HashMap, VecDeque};

use rieko_domain::{Channel, ChannelId, ChannelSnapshot};

/// Read-only history consumed by detectors. Detectors never write history;
/// the engine accumulates it each cycle.
pub trait HistoryView {
    /// Newest-first snapshots for a channel, at most `limit`.
    fn recent_channel_snapshots(
        &self,
        channel_id: &ChannelId,
        limit: usize,
    ) -> Vec<ChannelSnapshot>;
}

/// Bounded in-memory history buffer. The engine pushes one snapshot per
/// channel per cycle; old entries age out per channel.
#[derive(Debug, Default, Clone)]
pub struct InMemoryHistory {
    snapshots: HashMap<ChannelId, VecDeque<ChannelSnapshot>>,
    max_per_channel: usize,
}

impl InMemoryHistory {
    pub fn new(max_per_channel: usize) -> Self {
        Self {
            snapshots: HashMap::new(),
            max_per_channel,
        }
    }

    pub fn push(&mut self, snapshot: ChannelSnapshot) {
        let bucket = self.snapshots.entry(snapshot.channel_id()).or_default();
        bucket.push_back(snapshot);
        while bucket.len() > self.max_per_channel {
            bucket.pop_front();
        }
    }

    pub fn push_channels(&mut self, channels: &[Channel], ts: chrono::DateTime<chrono::Utc>) {
        for channel in channels {
            self.push(ChannelSnapshot::from_channel(channel, ts));
        }
    }

    pub fn len(&self) -> usize {
        self.snapshots.values().map(|q| q.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}

impl HistoryView for InMemoryHistory {
    fn recent_channel_snapshots(
        &self,
        channel_id: &ChannelId,
        limit: usize,
    ) -> Vec<ChannelSnapshot> {
        self.snapshots
            .get(channel_id)
            .map(|q| q.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rieko_domain::{ChannelStatus, LiquidityProfile, NodeId};

    fn snap(id: &str, ratio: f64) -> ChannelSnapshot {
        let capacity = 1_000_000u64;
        let local = (ratio * capacity as f64) as u64;
        ChannelSnapshot {
            node_id: Some("local-node".into()),
            channel_id: id.to_string(),
            local_ratio: ratio,
            local_balance_msat: local,
            remote_balance_msat: capacity - local,
            capacity_msat: capacity,
            status: ChannelStatus::Active,
            ts: chrono::Utc::now(),
            spendable_outbound_msat: 0,
            spendable_inbound_msat: 0,
        }
    }

    #[test]
    fn returns_newest_first_and_respects_limit() {
        let mut h = InMemoryHistory::new(100);
        for r in [0.5, 0.4, 0.3] {
            h.push(snap("c1", r));
        }
        let got = h.recent_channel_snapshots(&ChannelId::new("c1"), 2);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].local_ratio, 0.3);
        assert_eq!(got[1].local_ratio, 0.4);
    }

    #[test]
    fn bounds_per_channel() {
        let mut h = InMemoryHistory::new(3);
        for r in [0.9, 0.8, 0.7, 0.6, 0.5] {
            h.push(snap("c1", r));
        }
        let got = h.recent_channel_snapshots(&ChannelId::new("c1"), 10);
        assert_eq!(got.len(), 3);
        assert_eq!(got[got.len() - 1].local_ratio, 0.7);
    }

    #[test]
    fn push_channels_records_all() {
        let mut h = InMemoryHistory::new(10);
        let channels: Vec<Channel> = vec![Channel {
            id: ChannelId::new("c1"),
            node: NodeId::new("n"),
            peer: NodeId::new("p"),
            capacity_msat: 100_000,
            fee_policy: Default::default(),
            status: ChannelStatus::Active,
            liquidity: LiquidityProfile::compute(100_000, 40_000, 60_000),
            last_seen: chrono::Utc::now(),
            opening_height: None,
            channel_point: "tx:0".into(),
            local_reserve_msat: None,
            remote_reserve_msat: None,
            is_private: false,
            is_initiator: true,
            total_sent_msat: None,
            total_received_msat: None,
        }];
        h.push_channels(&channels, chrono::Utc::now());
        assert_eq!(h.len(), 1);
    }
}
