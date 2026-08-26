use chrono::{DateTime, Utc};
use rieko_domain::BitcoinNetwork;
use rieko_findings::{finding_identity, Evidence, Finding, FindingLifecycle, Severity};
use rieko_graph::GraphView;
use rieko_status::{OperationalState, SourceState};

use crate::{Detector, DetectorContext};

/// Correlates persisted BTCPay, Bitcoin Core, and Lightning state. The
/// detector is pure and performs no storage or network I/O.
pub struct LightningChainSyncCorrelationDetector {
    state: OperationalState,
}

impl LightningChainSyncCorrelationDetector {
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
        let lightning_at = self
            .state
            .lightning
            .as_ref()
            .map(|lightning| lightning.last_attempt);
        btcpay_at
            .into_iter()
            .chain(core_at)
            .chain(lightning_at)
            .max()
            .unwrap_or(DateTime::UNIX_EPOCH)
    }

    fn complete_state(
        &self,
    ) -> Option<(
        &rieko_status::BitcoinCoreState,
        &rieko_status::LightningState,
    )> {
        if !matches!(
            self.state.source,
            SourceState::BtcPayGreenfield { connected: true }
        ) {
            return None;
        }
        let core = self
            .state
            .bitcoin_core
            .as_ref()
            .filter(|core| core.connected && core.snapshot.is_some())?;
        let lightning = self
            .state
            .lightning
            .as_ref()
            .filter(|lightning| lightning.connected && lightning.snapshot.is_some())?;
        Some((core, lightning))
    }
}

impl Detector for LightningChainSyncCorrelationDetector {
    fn id(&self) -> &'static str {
        "lightning_chain_sync_correlation"
    }

    fn version(&self) -> &'static str {
        "1"
    }

    fn network_scope(&self, _ctx: &DetectorContext) -> Option<BitcoinNetwork> {
        None
    }

    fn run(&self, _view: &dyn GraphView, ctx: &DetectorContext) -> Vec<Finding> {
        let Some((core, lightning)) = self.complete_state() else {
            return Vec::new();
        };
        let core_snapshot = core
            .snapshot
            .as_ref()
            .expect("complete Core state includes a snapshot");
        let lightning_snapshot = lightning
            .snapshot
            .as_ref()
            .expect("complete Lightning state includes a snapshot");
        if !core_snapshot.synchronized || lightning_snapshot.synced_to_chain {
            return Vec::new();
        }
        let Some(node) = ctx.node else {
            return Vec::new();
        };
        let observed_at = self.observed_at();

        vec![Finding {
            id: finding_identity(self.id(), self.version(), None, Some(node), None),
            detector: self.id().into(),
            detector_version: self.version().into(),
            schema_version: rieko_findings::FINDING_SCHEMA_VERSION,
            severity: Severity::Warning,
            node: Some(node.into()),
            channel: None,
            evidence: vec![
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
                        "network": core_snapshot.network,
                        "block_height": core_snapshot.block_height,
                        "header_height": core_snapshot.header_height,
                        "synchronized": core_snapshot.synchronized,
                        "observed_at": core_snapshot.observed_at,
                    }),
                },
                Evidence {
                    key: "lightning_state".into(),
                    value: serde_json::json!({
                        "connected": lightning.connected,
                        "last_attempt": lightning.last_attempt,
                        "last_success": lightning.last_success,
                        "node_id": lightning_snapshot.node_id,
                        "synced_to_chain": lightning_snapshot.synced_to_chain,
                        "active_channels": lightning_snapshot.active_channels,
                        "inactive_channels": lightning_snapshot.inactive_channels,
                        "observed_at": lightning_snapshot.observed_at,
                    }),
                },
            ],
            provenance: None,
            explanation: Some(
                "BTCPay and Bitcoin Core are healthy and synchronized, but the connected LND node is not synchronized to chain."
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
    use rieko_domain::{BitcoinCoreSnapshot, LightningSnapshot};
    use rieko_graph::InMemoryGraph;
    use rieko_status::{BitcoinCoreState, LightningState};

    fn state(
        btcpay_connected: bool,
        core_connected: bool,
        core_synchronized: bool,
        lightning_connected: bool,
        lightning_synchronized: bool,
    ) -> OperationalState {
        let btcpay_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let core_at = Utc.timestamp_opt(1_700_000_100, 0).unwrap();
        let lightning_at = Utc.timestamp_opt(1_700_000_200, 0).unwrap();
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
                    block_height: 250,
                    header_height: 250,
                    synchronized: core_synchronized,
                    observed_at: core_at,
                }),
            }),
            lightning: Some(LightningState {
                connected: lightning_connected,
                last_attempt: lightning_at,
                last_success: lightning_connected.then_some(lightning_at),
                snapshot: Some(LightningSnapshot {
                    node_id: "02abcdef".into(),
                    synced_to_chain: lightning_synchronized,
                    active_channels: 3,
                    inactive_channels: 1,
                    observed_at: lightning_at,
                }),
            }),
            ..OperationalState::default()
        }
    }

    fn evaluate(state: OperationalState) -> crate::DetectorCycle {
        LightningChainSyncCorrelationDetector::new(state)
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
    fn healthy_core_and_unsynchronized_lightning_emit_typed_finding() {
        let cycle = evaluate(state(true, true, true, true, false));
        assert!(cycle.scope.complete);
        assert_eq!(cycle.findings.len(), 1);
        let finding = &cycle.findings[0];
        assert_eq!(finding.detector, "lightning_chain_sync_correlation");
        assert_eq!(finding.node.as_deref(), Some("btcpay-store:store-test"));
        assert_eq!(finding.lifecycle, FindingLifecycle::Active);
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
                "block_height": 250,
                "header_height": 250,
                "synchronized": true,
                "observed_at": "2023-11-14T22:15:00Z",
            }))
        );
        assert_eq!(
            finding.evidence_value("lightning_state"),
            Some(&serde_json::json!({
                "connected": true,
                "last_attempt": "2023-11-14T22:16:40Z",
                "last_success": "2023-11-14T22:16:40Z",
                "node_id": "02abcdef",
                "synced_to_chain": false,
                "active_channels": 3,
                "inactive_channels": 1,
                "observed_at": "2023-11-14T22:16:40Z",
            }))
        );
    }

    #[test]
    fn synchronized_lightning_or_unsynchronized_core_emit_nothing_from_complete_state() {
        for healthy in [
            state(true, true, true, true, true),
            state(true, true, false, true, false),
        ] {
            let cycle = evaluate(healthy);
            assert!(cycle.scope.complete);
            assert!(cycle.findings.is_empty());
        }
    }

    #[test]
    fn unavailable_or_missing_inputs_are_incomplete_and_silent() {
        for unavailable in [
            state(false, true, true, true, false),
            state(true, false, true, true, false),
            state(true, true, true, false, false),
        ] {
            let cycle = evaluate(unavailable);
            assert!(!cycle.scope.complete);
            assert!(cycle.findings.is_empty());
        }

        let cycle = evaluate(OperationalState {
            source: SourceState::BtcPayGreenfield { connected: true },
            ..OperationalState::default()
        });
        assert!(!cycle.scope.complete);
        assert!(cycle.findings.is_empty());
    }

    #[test]
    fn repeated_evaluation_uses_stable_logical_identity() {
        let state = state(true, true, true, true, false);
        let first = evaluate(state.clone());
        let second = evaluate(state);
        assert_eq!(first.findings[0].id, second.findings[0].id);
    }
}
