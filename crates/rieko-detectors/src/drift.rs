use chrono::Utc;
use rieko_domain::NodeId;
use rieko_findings::{finding_identity, Evidence, Finding, Severity};
use rieko_graph::GraphView;

use crate::registry::{Detector, DetectorContext};

/// Tunable thresholds for the liquidity-drift detector.
#[derive(Debug, Clone, Copy)]
pub struct DriftThresholds {
    /// How many recent snapshots to look back.
    pub window: usize,
    /// Minimum snapshots required before judging a trend.
    pub min_history: usize,
    /// Decline in `local_ratio` over the window to raise a warning.
    pub warn_decline: f64,
    /// Decline over the window to raise a critical (requires near-drained).
    pub critical_decline: f64,
    /// Only raise findings when current ratio is below this bar.
    pub warn_ratio_bar: f64,
}

impl Default for DriftThresholds {
    fn default() -> Self {
        Self {
            window: 12,
            min_history: 4,
            warn_decline: 0.05,
            critical_decline: 0.15,
            warn_ratio_bar: 0.25,
        }
    }
}

/// Detector #2: liquidity trend / drift. A channel can be healthy right now
/// yet be bleeding liquidity toward drained. This flags channels whose local
/// ratio is falling across recent snapshots, even before they cross the
/// hard low-water mark that `LiquidityDetector` watches.
pub struct DriftDetector {
    pub thresholds: DriftThresholds,
    pub local_node: NodeId,
}

impl DriftDetector {
    pub fn new(local_node: impl Into<NodeId>) -> Self {
        Self {
            thresholds: DriftThresholds::default(),
            local_node: local_node.into(),
        }
    }
}

impl Detector for DriftDetector {
    fn id(&self) -> &'static str {
        "liquidity_trend"
    }

    fn run(&self, view: &dyn GraphView, ctx: &DetectorContext) -> Vec<Finding> {
        let Some(history) = ctx.history else {
            return Vec::new();
        };

        let mut findings = Vec::new();
        for channel in view.channels() {
            if !channel.status.is_open() {
                continue;
            }
            let snaps = history.recent_channel_snapshots(&channel.id, self.thresholds.window);
            if snaps.len() < self.thresholds.min_history {
                continue;
            }

            let current = channel.liquidity.local_ratio;
            let start = snaps[snaps.len() - 1].local_ratio;
            let decline = start - current;
            if decline < self.thresholds.warn_decline || current >= self.thresholds.warn_ratio_bar {
                continue;
            }

            // Severity: steep decline while already low is critical.
            let severity = if decline >= self.thresholds.critical_decline {
                Severity::Critical
            } else {
                Severity::Warning
            };

            let min_in_window = snaps
                .iter()
                .map(|s| s.local_ratio)
                .fold(f64::INFINITY, f64::min);

            let evidence = vec![
                Evidence::text("direction", "draining"),
                Evidence::number("start_ratio", round4(start)),
                Evidence::number("current_ratio", round4(current)),
                Evidence::number("decline", round4(decline)),
                Evidence::number("min_in_window", round4(min_in_window)),
                Evidence::number("window", snaps.len() as f64),
                Evidence::text("peer", channel.peer.to_string()),
            ];

            findings.push(Finding {
                id: finding_identity(
                    self.id(),
                    self.version(),
                    severity,
                    Some(self.local_node.as_ref()),
                    Some(channel.id.as_ref()),
                    &evidence,
                ),
                detector: self.id().to_string(),
                severity,
                node: Some(self.local_node.to_string()),
                channel: Some(channel.id.to_string()),
                evidence,
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
    use rieko_domain::{Channel, ChannelStatus, FeePolicy, LiquidityProfile, NodeId};
    use rieko_graph::{GraphStore, InMemoryGraph, InMemoryHistory};

    use super::*;

    fn channel(id: &str, local_ratio: f64) -> Channel {
        let capacity = 1_000_000u64;
        let local = (local_ratio * capacity as f64) as u64;
        Channel {
            id: id.into(),
            node: NodeId::new("local-node"),
            peer: NodeId::new(format!("peer-{id}")),
            capacity_msat: capacity,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity: LiquidityProfile::compute(capacity, local, capacity - local),
            last_seen: Utc::now(),
            opening_height: Some(1),
        }
    }

    fn history_for(id: &str, ratios: &[f64]) -> InMemoryHistory {
        let mut h = InMemoryHistory::new(100);
        for r in ratios {
            let c = channel(id, *r);
            h.push(rieko_domain::ChannelSnapshot::from_channel(&c, Utc::now()));
        }
        h
    }

    fn ctx<'a>(h: &'a InMemoryHistory) -> DetectorContext<'a> {
        DetectorContext { history: Some(h) }
    }

    #[test]
    fn silent_without_enough_history() {
        let mut g = InMemoryGraph::new();
        g.upsert_channel(channel("c1", 0.10)).unwrap();
        let d = DriftDetector::new("local-node");
        assert!(d.run(&g, &DetectorContext::no_context()).is_empty());
    }

    #[test]
    fn flags_steady_drain() {
        let h = history_for("c1", &[0.35, 0.32, 0.28, 0.24]);
        let mut g = InMemoryGraph::new();
        g.upsert_channel(channel("c1", 0.24)).unwrap();
        let d = DriftDetector::new("local-node");
        let findings = d.run(&g, &ctx(&h));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].detector, "liquidity_trend");
    }

    #[test]
    fn steep_drain_while_low_is_critical() {
        let h = history_for("c1", &[0.40, 0.30, 0.18, 0.10, 0.05]);
        let mut g = InMemoryGraph::new();
        g.upsert_channel(channel("c1", 0.05)).unwrap();
        let d = DriftDetector::new("local-node");
        let findings = d.run(&g, &ctx(&h));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn healthy_channel_stays_silent() {
        let h = history_for("c1", &[0.50, 0.51, 0.49, 0.52, 0.51]);
        let mut g = InMemoryGraph::new();
        g.upsert_channel(channel("c1", 0.51)).unwrap();
        let d = DriftDetector::new("local-node");
        assert!(d.run(&g, &ctx(&h)).is_empty());
    }
}
