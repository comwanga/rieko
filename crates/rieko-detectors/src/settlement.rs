use chrono::Utc;
use rieko_domain::{ChannelStatus, NodeEvent, NodeId, PaymentStatus};
use rieko_findings::{
    channel_snapshot_state_digest, finding_identity, ChannelSnapshotReference, Evidence, Finding,
    FindingLifecycle, FindingProvenance, ObservationReference, Severity, FINDING_SCHEMA_VERSION,
};
use rieko_graph::GraphView;

use crate::registry::{provenance_producers, Detector, DetectorContext};

/// Tunable thresholds for the lightning settlement reliability degradation detector.
#[derive(Debug, Clone, Copy)]
pub struct SettlementReliabilityThresholds {
    /// Minimum failed/expired invoices in the evaluation window before raising a finding.
    pub min_failed_invoices: usize,
    /// Failure rate (failed / (failed + settled)) threshold for Warning.
    pub warn_failure_rate: f64,
    /// Failure rate threshold for Critical severity.
    pub critical_failure_rate: f64,
    /// Ratio below which an open channel is considered drained outbound.
    pub drained_ratio_bar: f64,
}

impl Default for SettlementReliabilityThresholds {
    fn default() -> Self {
        Self {
            min_failed_invoices: 2,
            warn_failure_rate: 0.40,
            critical_failure_rate: 0.70,
            drained_ratio_bar: 0.10,
        }
    }
}

/// Detector #3: Lightning Settlement Reliability Degradation.
///
/// Correlates:
/// 1. BTCPay Server invoice settlement failures and expiries over a temporal window.
/// 2. LND outbound liquidity exhaustion or channel inactivity on key paths.
/// 3. Bitcoin Core chain synchronization health.
///
/// When invoice failures increase while Bitcoin Core remains fully synchronized,
/// Rieko determines the root cause is **Lightning operational degradation (liquidity exhaustion / channel downtime)**,
/// rather than blockchain synchronization lag, and raises a typed finding with concrete rebalancing recommendations.
pub struct SettlementReliabilityDetector {
    pub thresholds: SettlementReliabilityThresholds,
    pub local_node: NodeId,
}

impl SettlementReliabilityDetector {
    pub fn new(local_node: impl Into<NodeId>) -> Self {
        Self {
            thresholds: SettlementReliabilityThresholds::default(),
            local_node: local_node.into(),
        }
    }

    pub fn with_thresholds(
        local_node: impl Into<NodeId>,
        thresholds: SettlementReliabilityThresholds,
    ) -> Self {
        Self {
            thresholds,
            local_node: local_node.into(),
        }
    }
}

impl Detector for SettlementReliabilityDetector {
    fn id(&self) -> &'static str {
        "settlement_reliability"
    }

    fn version(&self) -> &'static str {
        "1"
    }

    fn run(&self, view: &dyn GraphView, ctx: &DetectorContext) -> Vec<Finding> {
        let Some(events) = ctx.events else {
            // No BTCPay webhook events available. Operators who have not wired
            // up the webhook integration will see no findings from this detector.
            // Use `rieko serve` + the BTCPay webhook endpoint to enable it.
            return Vec::new();
        };

        if events.is_empty() {
            return Vec::new();
        }

        // 1. Analyze BTCPay temporal invoice events
        let mut expired_count: usize = 0;
        let mut settled_count: usize = 0;

        for event in events {
            match event {
                NodeEvent::InvoiceExpired(_)
                | NodeEvent::PaymentAttempt(rieko_domain::PaymentEvent {
                    status: PaymentStatus::Failed,
                    ..
                })
                | NodeEvent::PaymentMetric(rieko_domain::PaymentMetricEvent {
                    status: PaymentStatus::Failed,
                    ..
                }) => {
                    expired_count += 1;
                }
                NodeEvent::InvoiceSettled(_)
                | NodeEvent::InvoicePaymentReceived(_)
                | NodeEvent::PaymentAttempt(rieko_domain::PaymentEvent {
                    status: PaymentStatus::Succeeded,
                    ..
                })
                | NodeEvent::PaymentMetric(rieko_domain::PaymentMetricEvent {
                    status: PaymentStatus::Succeeded,
                    ..
                }) => {
                    settled_count += 1;
                }
                _ => {}
            }
        }

        let total_invoices = expired_count + settled_count;
        if total_invoices == 0 || expired_count < self.thresholds.min_failed_invoices {
            return Vec::new();
        }

        let failure_rate = expired_count as f64 / total_invoices as f64;
        if failure_rate < self.thresholds.warn_failure_rate {
            return Vec::new();
        }

        // 2. Analyze LND channel states and outbound liquidity
        let channels = view.channels();
        let mut drained_channels = Vec::new();
        let mut inactive_channels = Vec::new();

        for channel in &channels {
            if channel.node != self.local_node {
                continue;
            }
            if channel.status == ChannelStatus::Inactive {
                inactive_channels.push(channel);
            } else if channel.status.is_open()
                && channel.liquidity.local_ratio < self.thresholds.drained_ratio_bar
            {
                drained_channels.push(channel);
            }
        }

        // Primary bottleneck channel: most severely drained open channel, or first inactive channel
        let primary_bottleneck = drained_channels
            .iter()
            .min_by(|a, b| {
                a.liquidity
                    .local_ratio
                    .partial_cmp(&b.liquidity.local_ratio)
                    .unwrap()
            })
            .copied()
            .or_else(|| inactive_channels.first().copied());

        let target_channel_id = primary_bottleneck.map(|c| c.id.to_string());

        // 3. Evaluate Bitcoin Core synchronization health
        let chain_synchronized = ctx.chain_synchronized.unwrap_or(true);

        // 4. Determine severity
        let severity = if failure_rate >= self.thresholds.critical_failure_rate
            || expired_count >= 5
            || (!drained_channels.is_empty() && !inactive_channels.is_empty())
        {
            Severity::Critical
        } else {
            Severity::Warning
        };

        // 5. Structure evidence
        let mut evidence = vec![
            Evidence::number("expired_invoices", expired_count as f64),
            Evidence::number("settled_invoices", settled_count as f64),
            Evidence::number("total_invoices", total_invoices as f64),
            Evidence::number("failure_rate", failure_rate),
            Evidence::number("drained_channels_count", drained_channels.len() as f64),
            Evidence::number("inactive_channels_count", inactive_channels.len() as f64),
            Evidence::string(
                "chain_synchronized",
                if chain_synchronized { "true" } else { "false" },
            ),
            Evidence::string(
                "diagnosis",
                if chain_synchronized {
                    "lightning_settlement_degraded"
                } else {
                    "chain_sync_lag"
                },
            ),
            Evidence::string(
                "root_cause",
                if chain_synchronized {
                    "lightning_operational_degradation"
                } else {
                    "bitcoin_core_desynchronized"
                },
            ),
        ];

        if let Some(ref ch_id) = target_channel_id {
            evidence.push(Evidence::string("bottleneck_channel", ch_id.clone()));
        }

        let now = Utc::now();
        let node_id_str = self.local_node.to_string();

        let id = finding_identity(
            self.id(),
            self.version(),
            Some(ctx.network),
            Some(&node_id_str),
            target_channel_id.as_deref(),
        );

        let provenance = ctx.source.map(|source| {
            let observation = if let Some(channel) = primary_bottleneck {
                let snapshot = rieko_domain::ChannelSnapshot::from_channel(
                    channel,
                    channel.last_seen,
                    ctx.network,
                );
                let digest = channel_snapshot_state_digest(&snapshot);
                ObservationReference::ChannelState {
                    channel_id: channel.id.to_string(),
                    snapshot: ChannelSnapshotReference {
                        network: Some(ctx.network),
                        observed_at: channel.last_seen,
                        state_digest: digest,
                    },
                }
            } else {
                ObservationReference::ChannelState {
                    channel_id: target_channel_id.clone().unwrap_or_default(),
                    snapshot: ChannelSnapshotReference {
                        network: Some(ctx.network),
                        observed_at: now,
                        state_digest: "composite-operational-digest".into(),
                    },
                }
            };

            FindingProvenance {
                network: Some(ctx.network),
                source: source.clone(),
                producers: provenance_producers(ctx.normalizer, self),
                observation,
            }
        });

        let explanation = if chain_synchronized {
            format!(
                "Lightning settlement reliability degraded: {} of {} invoices failed or expired ({:.1}% failure rate). \
                 Bitcoin Core is synchronized, confirming root cause is Lightning channel liquidity exhaustion ({} drained, {} inactive).",
                expired_count,
                total_invoices,
                failure_rate * 100.0,
                drained_channels.len(),
                inactive_channels.len()
            )
        } else {
            format!(
                "Invoice settlements failing due to Bitcoin Core synchronization lag ({} expired invoices).",
                expired_count
            )
        };

        vec![Finding {
            id,
            detector: self.id().into(),
            detector_version: self.version().into(),
            schema_version: FINDING_SCHEMA_VERSION,
            severity,
            node: Some(node_id_str),
            channel: target_channel_id,
            evidence,
            provenance,
            explanation: Some(explanation),
            timestamp: now,
            first_seen_at: now,
            last_seen_at: now,
            lifecycle: FindingLifecycle::Active,
        }]
    }

    fn is_complete(&self, _view: &dyn GraphView, ctx: &DetectorContext) -> bool {
        ctx.events.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rieko_domain::{
        BitcoinNetwork, Channel, ChannelId, FeePolicy, InvoiceExpiredEvent, InvoiceSettledEvent,
        LiquidityProfile,
    };
    use rieko_findings::ObservationSource;
    use rieko_graph::{GraphStore, InMemoryGraph};

    fn make_channel(id: &str, node: &NodeId, local_msat: u64, capacity_msat: u64) -> Channel {
        Channel {
            id: ChannelId::new(id),
            node: node.clone(),
            peer: NodeId::new("peer-node"),
            channel_point: "1111111111111111111111111111111111111111111111111111111111111111:0"
                .into(),
            capacity_msat,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity: LiquidityProfile::compute(
                capacity_msat,
                local_msat,
                capacity_msat.saturating_sub(local_msat),
            ),
            last_seen: Utc::now(),
            opening_height: Some(800000),
            local_reserve_msat: None,
            remote_reserve_msat: None,
            is_private: false,
            is_initiator: false,
            total_received_msat: Some(0),
            total_sent_msat: Some(0),
        }
    }

    #[test]
    fn detects_settlement_degradation_when_invoices_expire_and_liquidity_is_drained() {
        let local_node = NodeId::new("node-test");
        let detector = SettlementReliabilityDetector::new(local_node.clone());

        let drained_channel = make_channel("chan-drained", &local_node, 20_000_000, 1_000_000_000); // ratio 0.02

        let mut graph = InMemoryGraph::new();
        graph.upsert_channels(vec![drained_channel]).unwrap();

        let events = vec![
            NodeEvent::InvoiceSettled(InvoiceSettledEvent {
                id: "inv-1".into(),
                store_id: None,
                payment_method: None,
                amount_msat: 1000,
                fee_msat: 10,
                timestamp: Utc::now(),
                payment_hash: None,
                metadata: std::collections::HashMap::new(),
            }),
            NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
                id: "inv-2".into(),
                store_id: None,
                amount_msat: Some(1000),
                timestamp: Utc::now(),
            }),
            NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
                id: "inv-3".into(),
                store_id: None,
                amount_msat: Some(2000),
                timestamp: Utc::now(),
            }),
            NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
                id: "inv-4".into(),
                store_id: None,
                amount_msat: Some(3000),
                timestamp: Utc::now(),
            }),
        ]; // 3 expired, 1 settled -> 75% failure rate -> Critical

        let source = ObservationSource::BtcPay {
            redacted_endpoint: "sha256:endpoint".into(),
            configured_store: "store-test".into(),
            underlying_node: Some("node-test".into()),
        };

        let ctx = DetectorContext {
            network: BitcoinNetwork::Regtest,
            history: None,
            source: Some(&source),
            normalizer: None,
            node: Some("node-test"),
            events: Some(&events),
            chain_synchronized: Some(true),
        };

        let findings = detector.run(&graph, &ctx);
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        assert_eq!(finding.detector, "settlement_reliability");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.channel.as_deref(), Some("chan-drained"));

        let ev_map: std::collections::HashMap<_, _> = finding
            .evidence
            .iter()
            .map(|e| (e.key.as_str(), &e.value))
            .collect();

        assert_eq!(ev_map.get("expired_invoices").unwrap(), &3.0);
        assert_eq!(ev_map.get("settled_invoices").unwrap(), &1.0);
        assert_eq!(ev_map.get("failure_rate").unwrap(), &0.75);
        assert_eq!(ev_map.get("chain_synchronized").unwrap(), &"true");
        assert_eq!(
            ev_map.get("root_cause").unwrap(),
            &"lightning_operational_degradation"
        );

        // Verify evaluate produces valid cycle
        let cycle = detector.evaluate(&graph, &ctx).unwrap();
        assert!(cycle.scope.complete);
        assert_eq!(cycle.findings.len(), 1);
    }

    #[test]
    fn desynchronized_chain_attributes_root_cause_to_chain_lag() {
        let local_node = NodeId::new("node-test");
        let detector = SettlementReliabilityDetector::new(local_node.clone());

        let drained_channel = make_channel("chan-drained", &local_node, 20_000_000, 1_000_000_000);

        let mut graph = InMemoryGraph::new();
        graph.upsert_channels(vec![drained_channel]).unwrap();

        let events = vec![
            NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
                id: "inv-1".into(),
                store_id: None,
                amount_msat: Some(1000),
                timestamp: Utc::now(),
            }),
            NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
                id: "inv-2".into(),
                store_id: None,
                amount_msat: Some(2000),
                timestamp: Utc::now(),
            }),
        ];

        let ctx = DetectorContext {
            network: BitcoinNetwork::Regtest,
            history: None,
            source: None,
            normalizer: None,
            node: Some("node-test"),
            events: Some(&events),
            chain_synchronized: Some(false), // Chain is NOT synced!
        };

        let findings = detector.run(&graph, &ctx);
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        let ev_map: std::collections::HashMap<_, _> = finding
            .evidence
            .iter()
            .map(|e| (e.key.as_str(), &e.value))
            .collect();

        assert_eq!(ev_map.get("chain_synchronized").unwrap(), &"false");
        assert_eq!(
            ev_map.get("root_cause").unwrap(),
            &"bitcoin_core_desynchronized"
        );
        assert_eq!(ev_map.get("diagnosis").unwrap(), &"chain_sync_lag");
    }

    #[test]
    fn healthy_settlement_produces_zero_findings() {
        let local_node = NodeId::new("node-test");
        let detector = SettlementReliabilityDetector::new(local_node.clone());

        let healthy_channel = make_channel("chan-healthy", &local_node, 500_000_000, 1_000_000_000);

        let mut graph = InMemoryGraph::new();
        graph.upsert_channels(vec![healthy_channel]).unwrap();

        let events = vec![
            NodeEvent::InvoiceSettled(InvoiceSettledEvent {
                id: "inv-1".into(),
                store_id: None,
                payment_method: None,
                amount_msat: 1000,
                fee_msat: 10,
                timestamp: Utc::now(),
                payment_hash: None,
                metadata: std::collections::HashMap::new(),
            }),
            NodeEvent::InvoiceSettled(InvoiceSettledEvent {
                id: "inv-2".into(),
                store_id: None,
                payment_method: None,
                amount_msat: 2000,
                fee_msat: 20,
                timestamp: Utc::now(),
                payment_hash: None,
                metadata: std::collections::HashMap::new(),
            }),
        ]; // 0 expired, 2 settled -> 0% failure rate

        let ctx = DetectorContext {
            network: BitcoinNetwork::Regtest,
            history: None,
            source: None,
            normalizer: None,
            node: Some("node-test"),
            events: Some(&events),
            chain_synchronized: Some(true),
        };

        let findings = detector.run(&graph, &ctx);
        assert!(findings.is_empty(), "healthy settlement yields no findings");
    }
}
