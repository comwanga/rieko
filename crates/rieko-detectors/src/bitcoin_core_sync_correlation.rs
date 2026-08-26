use chrono::{DateTime, Utc};
use rieko_domain::BitcoinNetwork;
use rieko_findings::{finding_identity, Evidence, Finding, FindingLifecycle, Severity};
use rieko_graph::GraphView;
use rieko_status::{OperationalState, SourceState};

use crate::{Detector, DetectorContext};

/// Correlates persisted BTCPay reachability with persisted Bitcoin Core sync
/// state. The detector is pure and performs no storage or network I/O.
pub struct BitcoinCoreSyncCorrelationDetector {
    state: OperationalState,
}

impl BitcoinCoreSyncCorrelationDetector {
    pub fn new(state: OperationalState) -> Self {
        Self { state }
    }

    fn observed_at(&self) -> DateTime<Utc> {
        let btcpay_at = self
            .state
            .last_ingestion_attempt
            .or(self.state.last_ingestion_success);
        let core_at = self
            .state
            .bitcoin_core
            .as_ref()
            .map(|core| core.last_attempt);
        btcpay_at
            .into_iter()
            .chain(core_at)
            .max()
            .unwrap_or(DateTime::UNIX_EPOCH)
    }

    fn complete_state(&self) -> Option<&rieko_status::BitcoinCoreState> {
        if !matches!(
            self.state.source,
            SourceState::BtcPayGreenfield { connected: true }
        ) {
            return None;
        }
        self.state
            .bitcoin_core
            .as_ref()
            .filter(|core| core.connected && core.snapshot.is_some())
    }
}

impl Detector for BitcoinCoreSyncCorrelationDetector {
    fn id(&self) -> &'static str {
        "bitcoin_core_sync_correlation"
    }

    fn version(&self) -> &'static str {
        "1"
    }

    fn network_scope(&self, _ctx: &DetectorContext) -> Option<BitcoinNetwork> {
        // The finding is scoped to the configured BTCPay store. Network is
        // retained as evidence without requiring new Core provenance types.
        None
    }

    fn run(&self, _view: &dyn GraphView, ctx: &DetectorContext) -> Vec<Finding> {
        let Some(core) = self.complete_state() else {
            return Vec::new();
        };
        let snapshot = core
            .snapshot
            .as_ref()
            .expect("complete Core state includes a snapshot");
        if snapshot.synchronized {
            return Vec::new();
        }
        let Some(node) = ctx.node else {
            return Vec::new();
        };
        let observed_at = self.observed_at();
        let evidence = vec![
            Evidence {
                key: "btcpay_state".into(),
                value: serde_json::json!({
                    "source": self.state.source.as_str(),
                    "connected": self.state.source.connected(),
                    "last_attempt": self.state.last_ingestion_attempt,
                    "last_success": self.state.last_ingestion_success,
                }),
            },
            Evidence {
                key: "bitcoin_core_state".into(),
                value: serde_json::json!({
                    "connected": core.connected,
                    "last_attempt": core.last_attempt,
                    "last_success": core.last_success,
                    "network": snapshot.network,
                    "block_height": snapshot.block_height,
                    "header_height": snapshot.header_height,
                    "synchronized": snapshot.synchronized,
                    "observed_at": snapshot.observed_at,
                }),
            },
        ];

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
                "BTCPay Greenfield is reachable, but the directly observed Bitcoin Core node is not synchronized."
                    .into(),
            ),
            timestamp: observed_at,
            first_seen_at: observed_at,
            last_seen_at: observed_at,
            lifecycle: FindingLifecycle::Active,
        }]
    }

    fn is_complete(&self, _view: &dyn GraphView, _ctx: &DetectorContext) -> bool {
        self.complete_state().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use rieko_domain::BitcoinCoreSnapshot;
    use rieko_graph::InMemoryGraph;
    use rieko_status::BitcoinCoreState;

    fn state(btcpay_connected: bool, core_connected: bool, synchronized: bool) -> OperationalState {
        let btcpay_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let core_at = Utc.timestamp_opt(1_700_000_100, 0).unwrap();
        OperationalState {
            source: SourceState::BtcPayGreenfield {
                connected: btcpay_connected,
            },
            last_ingestion_attempt: Some(btcpay_at),
            last_ingestion_success: btcpay_connected.then_some(btcpay_at),
            bitcoin_core: Some(BitcoinCoreState {
                connected: core_connected,
                last_attempt: core_at,
                last_success: core_connected.then_some(core_at),
                snapshot: Some(BitcoinCoreSnapshot {
                    network: BitcoinNetwork::Regtest,
                    block_height: 240,
                    header_height: 250,
                    synchronized,
                    observed_at: core_at,
                }),
            }),
            ..OperationalState::default()
        }
    }

    fn evaluate(state: OperationalState) -> crate::DetectorCycle {
        BitcoinCoreSyncCorrelationDetector::new(state)
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
    fn connected_btcpay_and_unsynchronized_core_emit_typed_finding() {
        let cycle = evaluate(state(true, true, false));
        assert!(cycle.scope.complete);
        assert_eq!(cycle.scope.network, None);
        assert_eq!(cycle.findings.len(), 1);
        let finding = &cycle.findings[0];
        assert_eq!(finding.detector, "bitcoin_core_sync_correlation");
        assert_eq!(finding.detector_version, "1");
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.node.as_deref(), Some("btcpay-store:store-test"));
        assert_eq!(finding.channel, None);
        assert_eq!(finding.lifecycle, FindingLifecycle::Active);
        assert_eq!(finding.provenance, None);
        assert_eq!(
            finding.evidence_value("btcpay_state"),
            Some(&serde_json::json!({
                "source": "btcpay_greenfield",
                "connected": true,
                "last_attempt": "2023-11-14T22:13:20Z",
                "last_success": "2023-11-14T22:13:20Z",
            }))
        );
        assert_eq!(
            finding.evidence_value("bitcoin_core_state"),
            Some(&serde_json::json!({
                "connected": true,
                "last_attempt": "2023-11-14T22:15:00Z",
                "last_success": "2023-11-14T22:15:00Z",
                "network": "regtest",
                "block_height": 240,
                "header_height": 250,
                "synchronized": false,
                "observed_at": "2023-11-14T22:15:00Z",
            }))
        );
    }

    #[test]
    fn synchronized_core_emits_no_finding_from_a_complete_cycle() {
        let cycle = evaluate(state(true, true, true));
        assert!(cycle.findings.is_empty());
        assert!(cycle.scope.complete);
    }

    #[test]
    fn unavailable_source_states_are_incomplete_and_silent() {
        for unavailable in [state(false, true, false), state(true, false, false)] {
            let cycle = evaluate(unavailable);
            assert!(cycle.findings.is_empty());
            assert!(!cycle.scope.complete);
        }

        let cycle = evaluate(OperationalState {
            source: SourceState::BtcPayGreenfield { connected: true },
            ..OperationalState::default()
        });
        assert!(cycle.findings.is_empty());
        assert!(!cycle.scope.complete);
    }
}
