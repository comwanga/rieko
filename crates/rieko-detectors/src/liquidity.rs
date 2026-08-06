use chrono::Utc;
use rieko_domain::{LiquidityImbalance, NodeId};
use rieko_findings::{finding_identity, Evidence, Finding, Severity};
use rieko_graph::GraphView;

use crate::registry::{Detector, DetectorContext};

/// Thresholds for the liquidity detector's *severity gate*. These are
/// documented heuristics, not universal truth (RIEKO-AUDIT-011).
///
/// The structural drain bands (e.g. `0.03`/`0.10`) are defined where they are
/// computed, in [`LiquidityProfile::compute`]. This struct only tunes how the
/// detector *grades severity* and therefore how loudly it reports.
#[derive(Debug, Clone, Copy)]
pub struct LiquidityThresholds {
    /// Local-ratio critical boundary. A drained channel whose local ratio is
    /// strictly below this (outbound) or above `1 - critical_ratio`
    /// (inbound) is reported `Critical`; otherwise it is `Warning`, even if
    /// the domain structurally classifies it as severely drained. Meaning:
    /// the detector's own critical bar. Unit: fraction of capacity
    /// (`0.0..=1.0`). Boundary: strict — a ratio exactly at the threshold is
    /// `Warning`. Configuration status: operator-tunable for v1. Rationale:
    /// a documented heuristic so that only genuinely near-empty channels
    /// demand `Critical`.
    pub critical_ratio: f64,
}

impl Default for LiquidityThresholds {
    fn default() -> Self {
        Self {
            critical_ratio: 0.05,
        }
    }
}

/// Detector #1 (ADR D8): channel liquidity / imbalance. Surfaces channels whose
/// liquidity is one-sided.
///
/// Findings are framed as a *liquidity condition / risk signal*, not proof of
/// a problem and not a command to rebalance (RIEKO-AUDIT-011). Invalid or
/// missing data (zero capacity, a balance exceeding capacity, or unknown
/// balance) is never classified as healthy or drained — such channels are
/// skipped. Only anomalies produce findings; healthy channels are silent.
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

    fn version(&self) -> &'static str {
        // v2: unknown/invalid liquidity is no longer classified as drained and
        // the severity gate is documented; semantics changed so identities bump.
        "2"
    }

    fn run(&self, view: &dyn GraphView, _ctx: &DetectorContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for channel in view.channels() {
            if !channel.status.is_open() {
                continue;
            }
            let profile = channel.liquidity;
            // Structural classification says only *whether* the channel is
            // imbalanced and on which side. Balanced and Unknown are skipped —
            // invalid/missing data is never a liquidity problem (RIEKO-AUDIT-011).
            let direction = match profile.imbalance {
                LiquidityImbalance::SeverelyDrained => {
                    if profile.local_ratio < 0.5 {
                        "outbound"
                    } else {
                        "inbound"
                    }
                }
                LiquidityImbalance::OutboundDrained => "outbound",
                LiquidityImbalance::InboundDrained => "inbound",
                LiquidityImbalance::Balanced | LiquidityImbalance::Unknown => continue,
            };

            // The detector's own critical bar (strict): ratios beyond it on
            // either side are Critical, otherwise Warning.
            let severity = if profile.local_ratio < self.thresholds.critical_ratio
                || profile.local_ratio > 1.0 - self.thresholds.critical_ratio
            {
                Severity::Critical
            } else {
                Severity::Warning
            };

            let evidence = vec![
                Evidence::text("direction", direction),
                Evidence::number("local_ratio", round4(profile.local_ratio)),
                Evidence::number("local_balance_msat", profile.local_balance_msat as f64),
                Evidence::number("remote_balance_msat", profile.remote_balance_msat as f64),
                Evidence::number("capacity_msat", channel.capacity_msat as f64),
                Evidence::text("peer", channel.peer.to_string()),
                // Show how the severity was judged so evidence is self-explanatory.
                Evidence::number("severity_threshold", self.thresholds.critical_ratio),
            ];

            let now = Utc::now();
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
                detector_version: self.version().to_string(),
                schema_version: rieko_findings::FINDING_SCHEMA_VERSION,
                severity,
                node: Some(self.local_node.to_string()),
                channel: Some(channel.id.to_string()),
                evidence,
                explanation: Some(format!(
                    "Liquidity on channel {} is one-sided ({direction} capacity drained, local ratio {:.4}). This is a risk signal, not proof of a fault; confirm the expected role and forwarding demand before acting.",
                    channel.id,
                    profile.local_ratio
                )),
                timestamp: now,
                first_seen_at: now,
                last_seen_at: now,
                lifecycle: rieko_findings::FindingLifecycle::Active,
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
    use rieko_graph::{GraphStore, InMemoryGraph};

    use super::*;
    use crate::registry::DetectorContext;

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
            channel_point: "tx:0".into(),
            local_reserve_msat: None,
            remote_reserve_msat: None,
            is_private: false,
            is_initiator: true,
            total_sent_msat: None,
            total_received_msat: None,
        }
    }

    fn raw_channel(id: &str, capacity: u64, profile: LiquidityProfile) -> Channel {
        Channel {
            id: id.into(),
            node: NodeId::new("local-node"),
            peer: NodeId::new(format!("peer-{id}")),
            capacity_msat: capacity,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity: profile,
            last_seen: Utc::now(),
            opening_height: Some(1),
            channel_point: "tx:0".into(),
            local_reserve_msat: None,
            remote_reserve_msat: None,
            is_private: false,
            is_initiator: true,
            total_sent_msat: None,
            total_received_msat: None,
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
        assert!(d.run(&g, &DetectorContext::no_context()).is_empty());
    }

    #[test]
    fn outbound_drained_yields_warning() {
        let g = graph_with(vec![channel("c1", 8_000, 92_000)]);
        let d = LiquidityDetector::new("local-node");
        let findings = d.run(&g, &DetectorContext::no_context());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].channel.as_deref(), Some("c1"));
    }

    #[test]
    fn critically_drained_yields_critical() {
        let g = graph_with(vec![channel("c1", 2_000, 98_000)]);
        let d = LiquidityDetector::new("local-node");
        let findings = d.run(&g, &DetectorContext::no_context());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].evidence_value("local_ratio").unwrap(),
            &serde_json::json!(0.02)
        );
    }

    #[test]
    fn closed_channels_are_skipped() {
        let mut c = channel("c1", 2_000, 98_000);
        c.status = ChannelStatus::Closed;
        let g = graph_with(vec![c]);
        let d = LiquidityDetector::new("local-node");
        assert!(d.run(&g, &DetectorContext::no_context()).is_empty());
    }

    #[test]
    fn sorted_most_severe_first() {
        let g = graph_with(vec![
            channel("c1", 8_000, 92_000),
            channel("c2", 1_000, 99_000),
        ]);
        let d = LiquidityDetector::new("local-node");
        let findings = d.run(&g, &DetectorContext::no_context());
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    // WP3.3 (RIEKO-AUDIT-011): invalid or unknown liquidity data must never be
    // classified as a healthy or drained channel.

    #[test]
    fn zero_capacity_is_not_classified() {
        let g = graph_with(vec![raw_channel(
            "c1",
            0,
            LiquidityProfile::compute(0, 0, 0),
        )]);
        let d = LiquidityDetector::new("local-node");
        assert!(
            d.run(&g, &DetectorContext::no_context()).is_empty(),
            "zero-capacity channel must not be flagged drained"
        );
    }

    #[test]
    fn balance_greater_than_capacity_is_not_classified() {
        let g = graph_with(vec![raw_channel(
            "c1",
            100_000,
            LiquidityProfile::compute(100_000, 120_000, 0),
        )]);
        let d = LiquidityDetector::new("local-node");
        assert!(
            d.run(&g, &DetectorContext::no_context()).is_empty(),
            "a balance above capacity is invalid data, not InboundDrained"
        );
    }

    #[test]
    fn missing_balance_is_not_classified() {
        let g = graph_with(vec![raw_channel(
            "c1",
            100_000,
            LiquidityProfile::unknown(),
        )]);
        let d = LiquidityDetector::new("local-node");
        assert!(
            d.run(&g, &DetectorContext::no_context()).is_empty(),
            "missing balance data is Unknown, not drained and not healthy"
        );
    }

    #[test]
    fn inactive_channel_is_skipped() {
        let mut c = channel("c1", 8_000, 92_000);
        c.status = ChannelStatus::Inactive;
        let g = graph_with(vec![c]);
        let d = LiquidityDetector::new("local-node");
        assert!(d.run(&g, &DetectorContext::no_context()).is_empty());
    }

    #[test]
    fn force_closing_channel_is_skipped() {
        let mut c = channel("c1", 8_000, 92_000);
        c.status = ChannelStatus::ForceClosing;
        let g = graph_with(vec![c]);
        let d = LiquidityDetector::new("local-node");
        assert!(d.run(&g, &DetectorContext::no_context()).is_empty());
    }

    #[test]
    fn exact_threshold_boundaries() {
        // 0.02 (< 0.03) is Critical and below the severity gate -> stays Critical.
        let g = graph_with(vec![channel("c1", 2_000, 98_000)]);
        let d = LiquidityDetector::new("local-node");
        assert_eq!(
            d.run(&g, &DetectorContext::no_context())[0].severity,
            Severity::Critical
        );

        // 0.03 is below the detector's strict critical bar (0.05) on the
        // drained side -> Critical.
        let g = graph_with(vec![channel("c1", 3_000, 97_000)]);
        let d = LiquidityDetector::new("local-node");
        assert_eq!(
            d.run(&g, &DetectorContext::no_context())[0].severity,
            Severity::Critical
        );

        // 0.06 sits between the critical bar and the drain floor -> Warning.
        let g = graph_with(vec![channel("c1", 6_000, 94_000)]);
        let d = LiquidityDetector::new("local-node");
        assert_eq!(
            d.run(&g, &DetectorContext::no_context())[0].severity,
            Severity::Warning
        );

        // 0.05 == critical_ratio: the bar is strict (`<`), so an exact hit is
        // Warning, not Critical.
        let g = graph_with(vec![raw_channel(
            "c1",
            100_000,
            LiquidityProfile::compute(100_000, 5_000, 95_000),
        )]);
        let d = LiquidityDetector::new("local-node");
        assert_eq!(
            d.run(&g, &DetectorContext::no_context())[0].severity,
            Severity::Warning
        );

        // 0.0499 < critical_ratio: below the bar on the drained side -> Critical.
        let g = graph_with(vec![raw_channel(
            "c1",
            100_000,
            LiquidityProfile::compute(100_000, 4_990, 95_010),
        )]);
        let d = LiquidityDetector::new("local-node");
        assert_eq!(
            d.run(&g, &DetectorContext::no_context())[0].severity,
            Severity::Critical
        );

        // Mirror on the inbound side: 0.98 (> 1 - 0.05) is Critical, 0.94 is not.
        let g = graph_with(vec![raw_channel(
            "c1",
            100_000,
            LiquidityProfile::compute(100_000, 98_000, 2_000),
        )]);
        let d = LiquidityDetector::new("local-node");
        assert_eq!(
            d.run(&g, &DetectorContext::no_context())[0].severity,
            Severity::Critical
        );
        let g = graph_with(vec![raw_channel(
            "c1",
            100_000,
            LiquidityProfile::compute(100_000, 94_000, 6_000),
        )]);
        let d = LiquidityDetector::new("local-node");
        assert_eq!(
            d.run(&g, &DetectorContext::no_context())[0].severity,
            Severity::Warning
        );

        // Exactly 0.10 is Balanced (drain floor is strict): silent.
        let g = graph_with(vec![raw_channel(
            "c1",
            100_000,
            LiquidityProfile::compute(100_000, 10_000, 90_000),
        )]);
        let d = LiquidityDetector::new("local-node");
        assert!(d.run(&g, &DetectorContext::no_context()).is_empty());
    }

    #[test]
    fn intentionally_imbalanced_input_is_flagged_as_a_condition() {
        // A deliberately one-sided channel is surfaced, but phrased as a risk
        // signal rather than proof of a fault.
        let g = graph_with(vec![channel("c1", 6_000, 94_000)]);
        let d = LiquidityDetector::new("local-node");
        let findings = d.run(&g, &DetectorContext::no_context());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        let explanation = findings[0].explanation.as_deref().unwrap_or("");
        assert!(
            explanation.contains("risk signal"),
            "detector phrasing must stay conditional, got: {explanation}"
        );
        assert_eq!(findings[0].detector_version, "2");
    }

    #[test]
    fn evidence_is_stable_and_shows_how_it_was_calculated() {
        let g = graph_with(vec![channel("c1", 2_000, 98_000)]);
        let d = LiquidityDetector::new("local-node");
        let a = d.run(&g, &DetectorContext::no_context());
        let b = d.run(&g, &DetectorContext::no_context());
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.evidence, y.evidence, "evidence must be deterministic");
            assert_eq!(x.id, y.id, "finding identity must be deterministic");
        }
        let f = &a[0];
        assert_eq!(
            f.evidence_value("local_ratio").unwrap(),
            &serde_json::json!(0.02)
        );
        assert_eq!(
            f.evidence_value("direction").unwrap(),
            &serde_json::json!("outbound")
        );
        assert_eq!(
            f.evidence_value("severity_threshold").unwrap(),
            &serde_json::json!(0.05),
            "evidence must show the severity threshold used"
        );
    }

    #[test]
    fn drained_finding_never_yields_a_direct_mutation() {
        use rieko_recommendations::RecommendationEngine;

        let g = graph_with(vec![channel("c1", 2_000, 98_000)]);
        let d = LiquidityDetector::new("local-node");
        let findings = d.run(&g, &DetectorContext::no_context());
        assert!(!findings.is_empty());

        let engine = RecommendationEngine;
        for f in &findings {
            let recs = engine.recommend(f).unwrap();
            for rec in recs {
                let params = rec.action.params;
                for banned in [
                    "desired_ratio",
                    "fee_rate_ppm",
                    "base_fee_msat",
                    "cltv_delta",
                    "method",
                ] {
                    assert!(
                        params.get(banned).is_none(),
                        "detector finding must not spawn a direct mutation ({banned})"
                    );
                }
            }
        }
    }
}
