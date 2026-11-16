use std::collections::BTreeMap;

use chrono::Duration;
use rieko_domain::{ChannelStatus, NodeEvent, NodeId};
use rieko_findings::{
    channel_snapshot_state_digest, finding_identity, ChannelSnapshotReference, Evidence, Finding,
    FindingLifecycle, FindingProvenance, ObservationReference, Severity, FINDING_SCHEMA_VERSION,
};
use rieko_graph::GraphView;

use crate::registry::{provenance_producers, Detector, DetectorContext};

/// Tunable thresholds for the lightning settlement reliability degradation detector.
#[derive(Debug, Clone, Copy)]
pub struct SettlementReliabilityThresholds {
    /// Time horizon for invoice evidence, evaluated against the caller clock.
    pub window: Duration,
    /// Minimum failed invoices in the evaluation window before raising a finding.
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
            window: Duration::minutes(60),
            min_failed_invoices: 2,
            warn_failure_rate: 0.40,
            critical_failure_rate: 0.70,
            drained_ratio_bar: 0.10,
        }
    }
}

/// Invoice settlement failures supported by explicit payment/lifecycle evidence.
/// Abandoned checkouts and unknown or pending outcomes are excluded from the
/// rate. Each store/invoice contributes at most once in the configured window.
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
        "2"
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

        let Some(window_start) = ctx.evaluated_at.checked_sub_signed(self.thresholds.window) else {
            return Vec::new();
        };
        if self.thresholds.window <= Duration::zero() {
            return Vec::new();
        }
        #[derive(Default)]
        struct InvoiceOutcome {
            failed: bool,
            settled: bool,
            abandoned: bool,
            unknown: bool,
            partial_expiry: bool,
        }
        let mut invoices: BTreeMap<(Option<String>, String), InvoiceOutcome> = BTreeMap::new();
        for event in events {
            if event.timestamp() < window_start || event.timestamp() > ctx.evaluated_at {
                continue;
            }
            let (id, store) = match event {
                NodeEvent::InvoiceSettled(e) | NodeEvent::InvoiceProcessing(e) => {
                    (&e.id, &e.store_id)
                }
                NodeEvent::InvoiceExpired(e) => (&e.id, &e.store_id),
                NodeEvent::InvoiceInvalid(e) => (&e.id, &e.store_id),
                NodeEvent::InvoicePaymentReceived(e) => (&e.id, &e.store_id),
                _ => continue,
            };
            let invoice = invoices.entry((store.clone(), id.clone())).or_default();
            match event {
                NodeEvent::InvoiceExpired(e) => match e.partially_paid {
                    Some(true) => {
                        invoice.failed = true;
                        invoice.partial_expiry = true;
                    }
                    Some(false) => invoice.abandoned = true,
                    None => invoice.unknown = true,
                },
                NodeEvent::InvoiceInvalid(e) => match e.manually_marked {
                    Some(false) => invoice.failed = true,
                    _ => invoice.unknown = true,
                },
                NodeEvent::InvoiceSettled(e) => match e.manually_marked {
                    Some(false) => invoice.settled = true,
                    _ => invoice.unknown = true,
                },
                NodeEvent::InvoicePaymentReceived(e) => match e.after_expiration {
                    Some(true) => invoice.failed = true,
                    Some(false) => {} // Receiving a payment does not prove settlement.
                    None => invoice.unknown = true,
                },
                _ => {} // Processing is pending, not settled.
            }
        }
        // Failure evidence takes precedence over eventual settlement. This is
        // a rate of invoices with failures observed in the window, not a claim
        // that an invoice never subsequently recovered. Unioning facts makes
        // redeliveries and out-of-order events deterministic.
        let failed_count = invoices.values().filter(|i| i.failed).count();
        let settled_count = invoices.values().filter(|i| !i.failed && i.settled).count();
        let abandoned_count = invoices
            .values()
            .filter(|i| !i.failed && !i.settled && i.abandoned)
            .count();
        let unknown_count = invoices
            .values()
            .filter(|i| !i.failed && !i.settled && !i.abandoned && i.unknown)
            .count();
        let pending_count =
            invoices.len() - failed_count - settled_count - abandoned_count - unknown_count;
        let expired_count = invoices.values().filter(|i| i.partial_expiry).count();
        let total_invoices = failed_count + settled_count;
        if total_invoices == 0 || failed_count < self.thresholds.min_failed_invoices {
            return Vec::new();
        }
        let failure_rate = failed_count as f64 / total_invoices as f64;
        if failure_rate < self.thresholds.warn_failure_rate {
            return Vec::new();
        }
        let mut invoice_ids: Vec<_> = invoices.keys().map(|(_, id)| id.clone()).collect();
        let mut store_ids: Vec<_> = invoices
            .keys()
            .filter_map(|(store, _)| store.clone())
            .collect();

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
        let chain_synchronized = ctx.chain_synchronized;
        let lightning_degradation_observed =
            !drained_channels.is_empty() || !inactive_channels.is_empty();

        // 4. Determine severity
        let severity = if failure_rate >= self.thresholds.critical_failure_rate {
            Severity::Critical
        } else {
            Severity::Warning
        };

        // 5. Structure evidence
        let mut evidence = vec![
            Evidence::number("failed_invoices", failed_count as f64),
            Evidence::number("abandoned_invoices", abandoned_count as f64),
            Evidence::number("unknown_invoices", unknown_count as f64),
            Evidence::number("pending_invoices", pending_count as f64),
            Evidence::number("observed_invoices", invoices.len() as f64),
            Evidence::number("window_seconds", self.thresholds.window.num_milliseconds() as f64 / 1000.0),
            Evidence::number("minimum_failed_invoices", self.thresholds.min_failed_invoices as f64),
            Evidence::number("warning_failure_rate", self.thresholds.warn_failure_rate),
            Evidence::number("critical_failure_rate", self.thresholds.critical_failure_rate),
            Evidence::string("window_started_at", window_start.to_rfc3339()),
            Evidence::string("window_ended_at", ctx.evaluated_at.to_rfc3339()),
            Evidence::string("failure_definition", "InvoiceExpired partially_paid=true, InvoiceInvalid manually_marked=false, or payment after_expiration=true; each store/invoice counted once; observed failure takes precedence over later settlement."),
            Evidence { key: "invoice_keys".into(), value: serde_json::json!(invoices.keys().map(|(store, id)| serde_json::json!({"store_id":store,"invoice_id":id})).collect::<Vec<_>>()) },
            Evidence::number("expired_invoices", expired_count as f64),
            Evidence::number("settled_invoices", settled_count as f64),
            Evidence::number("total_invoices", total_invoices as f64),
            Evidence::number("failure_rate", failure_rate),
            Evidence::number("drained_channels_count", drained_channels.len() as f64),
            Evidence::number("inactive_channels_count", inactive_channels.len() as f64),
            Evidence::string(
                "chain_synchronized",
                match chain_synchronized {
                    Some(true) => "true",
                    Some(false) => "false",
                    None => "unknown",
                },
            ),
            Evidence::string(
                "diagnosis",
                match (chain_synchronized, lightning_degradation_observed) {
                    (Some(false), _) => "chain_sync_lag",
                    (Some(true), true) => "lightning_settlement_degraded",
                    _ => "invoice_settlement_degraded",
                },
            ),
            Evidence::string(
                "root_cause",
                match (chain_synchronized, lightning_degradation_observed) {
                    (Some(false), _) => "bitcoin_core_desynchronized",
                    (Some(true), true) => "lightning_operational_degradation",
                    _ => "undetermined",
                },
            ),
        ];

        invoice_ids.sort();
        invoice_ids.dedup();
        store_ids.sort();
        store_ids.dedup();
        evidence.extend([
            Evidence {
                key: "invoice_ids".into(),
                value: serde_json::Value::Array(
                    invoice_ids
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            },
            Evidence {
                key: "store_ids".into(),
                value: serde_json::Value::Array(
                    store_ids
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            },
        ]);
        if let Some(ref ch_id) = target_channel_id {
            evidence.push(Evidence::string("bottleneck_channel", ch_id.clone()));
        }

        let now = ctx.evaluated_at;
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

        let observations = match (chain_synchronized, lightning_degradation_observed) {
            (Some(true), true) => format!("Core is synchronized; {} drained and {} inactive Lightning channels were also observed. These observations do not establish causation.", drained_channels.len(), inactive_channels.len()),
            (Some(false), _) => "Core is unsynchronized; this observation alone does not establish the cause of the invoice failures.".into(),
            _ => "The cause is undetermined from the available observations.".into(),
        };
        let explanation = format!(
            "Settlement failures were observed for {failed_count} of {total_invoices} eligible invoices ({:.1}% failure rate) in the last {} seconds. Each store/invoice is counted once. Excluded: {abandoned_count} abandoned, {unknown_count} unknown and {pending_count} pending invoices. {observations}",
            failure_rate * 100.0, self.thresholds.window.num_seconds()
        );

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
            && self.thresholds.window > Duration::zero()
            && ctx
                .evaluated_at
                .checked_sub_signed(self.thresholds.window)
                .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
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
                manually_marked: Some(false),
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
                partially_paid: Some(true),
                id: "inv-2".into(),
                store_id: None,
                amount_msat: Some(1000),
                timestamp: Utc::now(),
            }),
            NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
                partially_paid: Some(true),
                id: "inv-3".into(),
                store_id: None,
                amount_msat: Some(2000),
                timestamp: Utc::now(),
            }),
            NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
                partially_paid: Some(true),
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
            evaluated_at: chrono::Utc::now(),
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
                partially_paid: Some(true),
                id: "inv-1".into(),
                store_id: None,
                amount_msat: Some(1000),
                timestamp: Utc::now(),
            }),
            NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
                partially_paid: Some(true),
                id: "inv-2".into(),
                store_id: None,
                amount_msat: Some(2000),
                timestamp: Utc::now(),
            }),
        ];

        let ctx = DetectorContext {
            evaluated_at: chrono::Utc::now(),
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
                manually_marked: Some(false),
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
                manually_marked: Some(false),
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
            evaluated_at: chrono::Utc::now(),
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
