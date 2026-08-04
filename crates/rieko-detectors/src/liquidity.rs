use chrono::Utc;
use rieko_domain::{LiquidityImbalance, NodeId};
use rieko_findings::{Evidence, Finding, Severity};
use rieko_graph::GraphView;
use uuid::Uuid;

use crate::registry::Detector;

/// Tunable thresholds for liquidity severity. Detector severity is separate
/// from the structural imbalance classification in the domain model.
#[derive(Debug, Clone, Copy)]
pub struct LiquidityThresholds {
    /// local_ratio below this is `Critical`.
    pub critical_ratio: f64,
    /// local_ratio below this (and above critical) is `Warning`.
    pub warn_ratio: f64,
}

impl Default for LiquidityThresholds {
    fn default() -> Self {
        Self {
            critical_ratio: 0.05,
            warn_ratio: 0.15,
        }
    }
}

/// Detector #1 (ADR D8): channel liquidity / imbalance. Finds channels whose
/// liquidity is one-sided and recommends rebalancing (via `rieko-recommendations`).
///
/// Only anomalies produce findings — healthy channels are silent.
pub struct LiquidityDetector {
    pub thresholds: LiquidityThresholds,
    pub local_node: NodeId,
}

impl LiquidityDetector {
    pub fn new(local_node: impl Into<NodeId>) -> Self {
        Self {
            thresholds: LiquidityThresholds::default(),
            local_node: local_node.into(),
        }
    }
}

impl Detector for LiquidityDetector {
    fn id(&self) -> &'static str {
        "channel_liquidity"
    }

    fn run(&self, view: &dyn GraphView) -> Vec<Finding> {
        let mut findings = Vec::new();
        for channel in view.channels() {
            if !channel.status.is_open() {
                continue;
            }
            let profile = channel.liquidity;
            let (severity, direction) = match profile.imbalance {
                LiquidityImbalance::SeverelyDrained => (
                    Severity::Critical,
                    if profile.local_ratio < 0.5 {
                        "outbound"
                    } else {
                        "inbound"
                    },
                ),
                LiquidityImbalance::OutboundDrained => (Severity::Warning, "outbound"),
                LiquidityImbalance::InboundDrained => (Severity::Warning, "inbound"),
                LiquidityImbalance::Balanced => continue,
            };

            // Apply detector thresholds: a mildly-drained channel in the domain
            // model stays Warning unless it crosses the detector's critical bar.
            let severity = if severity == Severity::Critical
                && profile.local_ratio >= self.thresholds.critical_ratio
            {
                Severity::Warning
            } else {
                severity
            };

            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                detector: self.id().to_string(),
                severity,
                node: Some(self.local_node.to_string()),
                channel: Some(channel.id.to_string()),
                evidence: vec![
                    Evidence::text("direction", direction),
                    Evidence::number("local_ratio", round4(profile.local_ratio)),
                    Evidence::number("local_balance_msat", profile.local_balance_msat as f64),
                    Evidence::number("remote_balance_msat", profile.remote_balance_msat as f64),
                    Evidence::number("capacity_msat", channel.capacity_msat as f64),
                    Evidence::text("peer", channel.peer.to_string()),
                ],
                explanation: None,
                timestamp: Utc::now(),
            });
        }
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
        findings
    }
}

fn round4(v: f64) -> f64 {
    (v * 10_000.0).round() / 10_000.0
}

#[cfg(test)]
mod tests {
    use rieko_domain::{
        Channel, ChannelStatus, FeePolicy, LiquidityProfile, NodeId,
    };
    use rieko_graph::{GraphStore, InMemoryGraph};

    use super::*;

    fn channel(id: &str, local: u64, remote: u64) -> Channel {
        let capacity = local + remote;
        Channel {
            id: id.into(),
            node: NodeId::new("local-node"),
            peer: NodeId::new(format!("peer-{id}")),
            capacity_msat: capacity,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity: LiquidityProfile::compute(capacity, local, remote),
            last_seen: Utc::now(),
            opening_height: Some(1),
        }
    }

    fn graph_with(channels: Vec<Channel>) -> InMemoryGraph {
        let mut g = InMemoryGraph::new();
        g.upsert_channels(channels).unwrap();
        g
    }

    #[test]
    fn balanced_channel_is_silent() {
        let g = graph_with(vec![channel("c1", 50_000, 50_000)]);
        let d = LiquidityDetector::new("local-node");
        assert!(d.run(&g).is_empty());
    }

    #[test]
    fn outbound_drained_yields_warning() {
        let g = graph_with(vec![channel("c1", 8_000, 92_000)]);
        let d = LiquidityDetector::new("local-node");
        let findings = d.run(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].channel.as_deref(), Some("c1"));
    }

    #[test]
    fn critically_drained_yields_critical() {
        let g = graph_with(vec![channel("c1", 2_000, 98_000)]);
        let d = LiquidityDetector::new("local-node");
        let findings = d.run(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].evidence_value("local_ratio").unwrap(), &serde_json::json!(0.02));
    }

    #[test]
    fn closed_channels_are_skipped() {
        let mut c = channel("c1", 2_000, 98_000);
        c.status = ChannelStatus::Closed;
        let g = graph_with(vec![c]);
        let d = LiquidityDetector::new("local-node");
        assert!(d.run(&g).is_empty());
    }

    #[test]
    fn sorted_most_severe_first() {
        let g = graph_with(vec![
            channel("c1", 8_000, 92_000),
            channel("c2", 1_000, 99_000),
        ]);
        let d = LiquidityDetector::new("local-node");
        let findings = d.run(&g);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
