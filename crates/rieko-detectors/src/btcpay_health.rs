use chrono::{DateTime, Utc};
use rieko_domain::BitcoinNetwork;
use rieko_findings::{finding_identity, Evidence, Finding, FindingLifecycle, Severity};
use rieko_graph::GraphView;
use rieko_status::{OperationalState, SourceState};

use crate::{Detector, DetectorContext};

/// Detects one condition: the persisted BTCPay Greenfield source is unreachable.
///
/// The detector is deliberately pure. It receives an already-persisted runtime
/// state snapshot and performs no API, storage, or LLM work.
pub struct BtcPayBackendHealthDetector {
    state: OperationalState,
}

impl BtcPayBackendHealthDetector {
    pub fn new(state: OperationalState) -> Self {
        Self { state }
    }

    fn observed_at(&self) -> DateTime<Utc> {
        self.state
            .last_ingestion_attempt
            .or(self.state.last_ingestion_success)
            .unwrap_or(DateTime::UNIX_EPOCH)
    }
}

impl Detector for BtcPayBackendHealthDetector {
    fn id(&self) -> &'static str {
        "btcpay_backend_health"
    }

    fn version(&self) -> &'static str {
        "1"
    }

    fn network_scope(&self, _ctx: &DetectorContext) -> Option<BitcoinNetwork> {
        // Greenfield reachability is scoped to the configured BTCPay store,
        // not to a chain-specific channel observation.
        None
    }

    fn run(&self, _view: &dyn GraphView, ctx: &DetectorContext) -> Vec<Finding> {
        if !matches!(
            self.state.source,
            SourceState::BtcPayGreenfield { connected: false }
        ) {
            return Vec::new();
        }
        let Some(node) = ctx.node else {
            return Vec::new();
        };
        let observed_at = self.observed_at();
        let evidence = vec![Evidence {
            key: "operational_state".into(),
            value: serde_json::json!({
                "source": self.state.source.as_str(),
                "connected": self.state.source.connected(),
                "last_ingestion_attempt": self.state.last_ingestion_attempt,
                "last_ingestion_success": self.state.last_ingestion_success,
            }),
        }];

        vec![Finding {
            id: finding_identity(self.id(), self.version(), None, Some(node), None),
            detector: self.id().into(),
            detector_version: self.version().into(),
            schema_version: rieko_findings::FINDING_SCHEMA_VERSION,
            severity: Severity::Warning,
            node: Some(node.into()),
            channel: None,
            evidence,
            provenance: None,
            explanation: Some(
                "The persisted BTCPay Greenfield source is unreachable; the agent will retry on its next configured polling cycle."
                    .into(),
            ),
            timestamp: observed_at,
            first_seen_at: observed_at,
            last_seen_at: observed_at,
            lifecycle: FindingLifecycle::Active,
        }]
    }

    fn is_complete(&self, _view: &dyn GraphView, _ctx: &DetectorContext) -> bool {
        matches!(self.state.source, SourceState::BtcPayGreenfield { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use rieko_domain::BitcoinNetwork;
    use rieko_graph::InMemoryGraph;

    fn state(connected: bool) -> OperationalState {
        OperationalState {
            source: SourceState::BtcPayGreenfield { connected },
            last_ingestion_attempt: Some(Utc.timestamp_opt(1_700_000_000, 0).unwrap()),
            last_ingestion_success: connected.then(|| Utc.timestamp_opt(1_699_999_900, 0).unwrap()),
            ..OperationalState::default()
        }
    }

    fn evaluate(state: OperationalState) -> crate::DetectorCycle {
        BtcPayBackendHealthDetector::new(state)
            .evaluate(
                &InMemoryGraph::new(),
                &DetectorContext {
                    node: Some("btcpay-store:store-test"),
                    ..DetectorContext::no_context(BitcoinNetwork::Regtest)
                },
            )
            .unwrap()
    }

    #[test]
    fn healthy_persisted_state_emits_no_finding() {
        let cycle = evaluate(state(true));
        assert!(cycle.findings.is_empty());
        assert!(cycle.scope.complete);
        assert_eq!(cycle.scope.network, None);
    }

    #[test]
    fn disconnected_persisted_state_emits_one_typed_finding_with_exact_evidence() {
        let cycle = evaluate(state(false));
        assert_eq!(cycle.findings.len(), 1);
        let finding = &cycle.findings[0];
        assert_eq!(finding.detector, "btcpay_backend_health");
        assert_eq!(finding.detector_version, "1");
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.node.as_deref(), Some("btcpay-store:store-test"));
        assert_eq!(finding.channel, None);
        assert_eq!(finding.lifecycle, FindingLifecycle::Active);
        assert_eq!(finding.provenance, None);
        assert_eq!(
            finding.evidence_value("operational_state"),
            Some(&serde_json::json!({
                "source": "btcpay_greenfield",
                "connected": false,
                "last_ingestion_attempt": "2023-11-14T22:13:20Z",
                "last_ingestion_success": null,
            }))
        );
    }

    #[test]
    fn an_unrelated_persisted_source_is_incomplete_and_silent() {
        let cycle = evaluate(OperationalState::default());
        assert!(cycle.findings.is_empty());
        assert!(!cycle.scope.complete);
    }
}
