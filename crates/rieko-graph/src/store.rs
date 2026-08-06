use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rieko_domain::{Channel, ChannelId, ForwardEvent, Node, NodeId, PaymentEvent};
use thiserror::Error;

use crate::path::{self, Path};

#[derive(Debug, Error)]
pub enum GraphError {
    #[error("node {0} not found")]
    NodeNotFound(NodeId),
    #[error("channel {0} not found")]
    ChannelNotFound(ChannelId),
}

/// Read-only view of the graph that detectors consume. Detectors must never
/// mutate the graph: they see a snapshot and return findings.
pub trait GraphView {
    fn nodes(&self) -> Vec<&Node>;
    fn node(&self, id: &NodeId) -> Option<&Node>;
    fn channels(&self) -> Vec<&Channel>;
    fn channel(&self, id: &ChannelId) -> Option<&Channel>;
    fn channels_for_peer(&self, peer: &NodeId) -> Vec<&Channel>;
    fn recent_forwards(&self, limit: usize) -> Vec<&ForwardEvent>;
    fn recent_payments(&self, limit: usize) -> Vec<&PaymentEvent>;
}

/// Write side of the graph. All writes are idempotent upserts keyed by entity
/// id, which (with the per-source last-seen ledger) satisfies the D9 replay
/// constraint.
pub trait GraphStore: GraphView {
    fn upsert_node(&mut self, node: Node) -> GraphResult<()>;
    fn upsert_channel(&mut self, channel: Channel) -> GraphResult<()>;
    fn upsert_channels(&mut self, channels: Vec<Channel>) -> GraphResult<usize>;
    fn record_forward(&mut self, event: ForwardEvent);
    fn record_payment(&mut self, event: PaymentEvent);

    /// Advance the per-source ingestion ledger. Idempotency: sources should
    /// skip events older than the last seen marker.
    fn mark_source_seen(&mut self, source: &str, at: DateTime<Utc>);
    fn source_last_seen(&self, source: &str) -> Option<DateTime<Utc>>;
}

pub type GraphResult<T> = Result<T, GraphError>;

/// In-memory graph. Single-binary v1 keeps the live graph in memory; durable
/// records (findings, actions, audit, source ledger) live in `rieko-storage`.
#[derive(Debug, Default, Clone)]
pub struct InMemoryGraph {
    nodes: HashMap<NodeId, Node>,
    channels: HashMap<ChannelId, Channel>,
    forwards: Vec<ForwardEvent>,
    payments: Vec<PaymentEvent>,
    source_ledger: HashMap<String, DateTime<Utc>>,
    /// Adjacency index mapping each node (local and peers) to its channel IDs.
    /// Maintained by `upsert_channel`; enables O(1) `channels_for_peer` and
    /// Dijkstra path-finding (Phase 7.2).
    peer_channels: HashMap<NodeId, Vec<ChannelId>>,
}

impl InMemoryGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> (usize, usize) {
        (self.nodes.len(), self.channels.len())
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.channels.is_empty()
    }

    /// Find the cheapest path from `source` to `target` for `amount_msat`
    /// through the channel graph. Returns `None` if no route exists.
    pub fn find_path(&self, source: &NodeId, target: &NodeId, amount_msat: u64) -> Option<Path> {
        path::find_path(
            source,
            target,
            amount_msat,
            &self.channels,
            &self.peer_channels,
        )
    }

    /// Total capacity across all channels with a given peer.
    pub fn total_capacity_with_peer(&self, peer: &NodeId) -> u64 {
        self.peer_channels
            .get(peer)
            .map(|ids| {
                ids.iter()
                    .filter_map(|cid| self.channels.get(cid))
                    .map(|c| c.capacity_msat)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Number of open channels with a given peer.
    pub fn channel_count_with_peer(&self, peer: &NodeId) -> usize {
        self.peer_channels
            .get(peer)
            .map(|ids| {
                ids.iter()
                    .filter(|cid| {
                        self.channels
                            .get(cid)
                            .map(|c| c.status.is_open())
                            .unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0)
    }
}

impl GraphView for InMemoryGraph {
    fn nodes(&self) -> Vec<&Node> {
        self.nodes.values().collect()
    }

    fn node(&self, id: &NodeId) -> Option<&Node> {
        self.nodes.get(id)
    }

    fn channels(&self) -> Vec<&Channel> {
        self.channels.values().collect()
    }

    fn channel(&self, id: &ChannelId) -> Option<&Channel> {
        self.channels.get(id)
    }

    fn channels_for_peer(&self, peer: &NodeId) -> Vec<&Channel> {
        self.peer_channels
            .get(peer)
            .map(|ids| {
                ids.iter()
                    .filter_map(|cid| self.channels.get(cid))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn recent_forwards(&self, limit: usize) -> Vec<&ForwardEvent> {
        self.forwards.iter().rev().take(limit).collect()
    }

    fn recent_payments(&self, limit: usize) -> Vec<&PaymentEvent> {
        self.payments.iter().rev().take(limit).collect()
    }
}

impl GraphStore for InMemoryGraph {
    fn upsert_node(&mut self, node: Node) -> GraphResult<()> {
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    fn upsert_channel(&mut self, channel: Channel) -> GraphResult<()> {
        // Remove old entry from adjacency index if the channel is being replaced.
        if let Some(old) = self.channels.get(&channel.id) {
            if old.peer != channel.peer {
                if let Some(list) = self.peer_channels.get_mut(&old.peer) {
                    list.retain(|cid| cid != &channel.id);
                }
                if let Some(list) = self.peer_channels.get_mut(&channel.node) {
                    list.retain(|cid| cid != &channel.id);
                }
            }
        }

        self.nodes
            .entry(channel.peer.clone())
            .or_insert_with(|| Node {
                id: channel.peer.clone(),
                alias: None,
                version: None,
                status: rieko_domain::NodeStatus::Unknown,
                last_seen: channel.last_seen,
            });

        // Track in adjacency: peer → channel, node → channel (bidirectional).
        self.peer_channels
            .entry(channel.peer.clone())
            .or_default()
            .push(channel.id.clone());
        self.peer_channels
            .entry(channel.node.clone())
            .or_default()
            .push(channel.id.clone());

        self.channels.insert(channel.id.clone(), channel);
        Ok(())
    }

    fn upsert_channels(&mut self, channels: Vec<Channel>) -> GraphResult<usize> {
        let n = channels.len();
        for channel in channels {
            self.upsert_channel(channel)?;
        }
        Ok(n)
    }

    fn record_forward(&mut self, event: ForwardEvent) {
        self.forwards.push(event);
    }

    fn record_payment(&mut self, event: PaymentEvent) {
        self.payments.push(event);
    }

    fn mark_source_seen(&mut self, source: &str, at: DateTime<Utc>) {
        self.source_ledger.insert(source.to_string(), at);
    }

    fn source_last_seen(&self, source: &str) -> Option<DateTime<Utc>> {
        self.source_ledger.get(source).copied()
    }
}

#[cfg(test)]
mod tests {
    use rieko_domain::{Channel, ChannelStatus, FeePolicy, LiquidityProfile, NodeId};

    use super::*;

    fn channel(id: &str, peer: &str, local: u64, remote: u64) -> Channel {
        let capacity = local + remote;
        Channel {
            id: ChannelId::new(id),
            node: NodeId::new("local-node"),
            peer: NodeId::new(peer),
            capacity_msat: capacity,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity: LiquidityProfile::compute(capacity, local, remote),
            last_seen: Utc::now(),
            opening_height: Some(100),
            channel_point: "tx:0".into(),
            local_reserve_msat: None,
            remote_reserve_msat: None,
            is_private: false,
            is_initiator: true,
            total_sent_msat: None,
            total_received_msat: None,
        }
    }

    #[test]
    fn upsert_is_idempotent_and_replaces() {
        let mut g = InMemoryGraph::new();
        g.upsert_channel(channel("c1", "peer1", 40_000, 60_000))
            .unwrap();
        g.upsert_channel(channel("c1", "peer1", 10_000, 90_000))
            .unwrap();
        let c = g.channel(&ChannelId::new("c1")).unwrap();
        assert_eq!(c.liquidity.local_balance_msat, 10_000);
        assert_eq!(g.channels().len(), 1);
    }

    #[test]
    fn upserting_channel_creates_peer_node() {
        let mut g = InMemoryGraph::new();
        g.upsert_channel(channel("c1", "peer9", 50_000, 50_000))
            .unwrap();
        assert!(g.node(&NodeId::new("peer9")).is_some());
    }

    #[test]
    fn source_ledger_tracks_last_seen() {
        let mut g = InMemoryGraph::new();
        let t1 = Utc::now();
        g.mark_source_seen("lnd", t1);
        assert_eq!(g.source_last_seen("lnd"), Some(t1));
        assert_eq!(g.source_last_seen("core"), None);
    }
}
