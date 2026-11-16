use chrono::{DateTime, Utc};
use rieko_domain::BitcoinNetwork;
use rieko_findings::{finding_identity, Evidence, Finding, FindingLifecycle, Severity};
use rieko_graph::GraphView;
use rieko_status::OperationalState;

use crate::{Detector, DetectorContext};

/// Consecutive failed polls before a source is reported. This is a
/// heuristic chosen to ignore a single dropped request; it is not derived from
/// any property of the source.
pub const SOURCE_FAILURE_THRESHOLD: u32 = 3;

/// A directly polled source whose poll outcomes are tracked independently of the
/// BTCPay Greenfield source slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolledSource {
    BitcoinCore,
    Lnd,
}

impl PolledSource {
    /// Fixed finding scope. LND's public key is unknown until its first
    /// successful poll, so the identity cannot depend on it.
    pub fn node_label(self) -> &'static str {
        match self {
            Self::BitcoinCore => "bitcoin-core",
            Self::Lnd => "lnd-rest",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::BitcoinCore => "Bitcoin Core RPC",
            Self::Lnd => "LND REST",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Observation {
    connected: bool,
    consecutive_failures: u32,
    last_attempt: DateTime<Utc>,
    last_success: Option<DateTime<Utc>>,
    snapshot_observed_at: Option<DateTime<Utc>>,
}

/// Detects one condition: a polled source has failed
/// [`SOURCE_FAILURE_THRESHOLD`] or more consecutive polls. A failed poll is any
/// poll without a usable answer: no connection, a timeout, an HTTP or RPC
/// error, rejected credentials or a malformed response. The detector does not
/// know which, and its explanation does not say.
///
/// The detector is pure. It reads an already-persisted runtime state and
/// performs no API, storage, clock or LLM work.
pub struct SourcePollFailureDetector {
    source: PolledSource,
    observation: Option<Observation>,
}

impl SourcePollFailureDetector {
    pub fn new(source: PolledSource, state: &OperationalState) -> Self {
        let observation = match source {
            PolledSource::BitcoinCore => state.bitcoin_core.as_ref().map(|core| Observation {
                connected: core.connected,
                consecutive_failures: core.consecutive_failures,
                last_attempt: core.last_attempt,
                last_success: core.last_success,
                snapshot_observed_at: core.snapshot.as_ref().map(|snapshot| snapshot.observed_at),
            }),
            PolledSource::Lnd => state.lightning.as_ref().map(|lightning| Observation {
                connected: lightning.connected,
                consecutive_failures: lightning.consecutive_failures,
                last_attempt: lightning.last_attempt,
                last_success: lightning.last_success,
                snapshot_observed_at: lightning
                    .snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.observed_at),
            }),
        };
        Self {
            source,
            observation,
        }
    }

    fn failing(&self) -> Option<&Observation> {
        self.observation.as_ref().filter(|observation| {
            !observation.connected && observation.consecutive_failures >= SOURCE_FAILURE_THRESHOLD
        })
    }
}

impl Detector for SourcePollFailureDetector {
    fn id(&self) -> &'static str {
        match self.source {
            PolledSource::BitcoinCore => "bitcoin_core_poll_failure",
            PolledSource::Lnd => "lnd_poll_failure",
        }
    }

    fn version(&self) -> &'static str {
        "1"
    }

    fn network_scope(&self, _ctx: &DetectorContext) -> Option<BitcoinNetwork> {
        // Poll failures describe the configured endpoint, not a chain.
        None
    }

    fn run(&self, _view: &dyn GraphView, ctx: &DetectorContext) -> Vec<Finding> {
        let Some(observation) = self.failing() else {
            return Vec::new();
        };
        let Some(node) = ctx.node else {
            return Vec::new();
        };
        let evidence = vec![Evidence {
            key: "source_state".into(),
            value: serde_json::json!({
                "connected": observation.connected,
                "consecutive_failures": observation.consecutive_failures,
                "failure_threshold": SOURCE_FAILURE_THRESHOLD,
                "last_attempt": observation.last_attempt,
                "last_success": observation.last_success,
                "last_snapshot_observed_at": observation.snapshot_observed_at,
            }),
        }];
        let last_success = match observation.last_success {
            Some(at) => format!("the last successful poll was at {}", at.to_rfc3339()),
            None => "no successful poll has been recorded".to_string(),
        };

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
            explanation: Some(format!(
                "The last {} consecutive {} polls failed; {}. The agent retries on each polling cycle.",
                observation.consecutive_failures,
                self.source.display_name(),
                last_success,
            )),
            timestamp: observation.last_attempt,
            first_seen_at: observation.last_attempt,
            last_seen_at: observation.last_attempt,
            lifecycle: FindingLifecycle::Active,
        }]
    }

    fn is_complete(&self, _view: &dyn GraphView, _ctx: &DetectorContext) -> bool {
        // A disconnected source below the threshold is neither answering nor
        // yet reported, so that cycle says nothing about the finding's absence.
        self.observation
            .as_ref()
            .is_some_and(|observation| observation.connected)
            || self.failing().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use rieko_domain::{BitcoinCoreSnapshot, LightningSnapshot};
    use rieko_graph::InMemoryGraph;
    use rieko_status::{BitcoinCoreState, LightningState};

    const SOURCES: [PolledSource; 2] = [PolledSource::BitcoinCore, PolledSource::Lnd];

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + seconds, 0).unwrap()
    }

    /// A state in which `source` has the given poll history and the other
    /// polled source is absent.
    fn state(
        source: PolledSource,
        connected: bool,
        consecutive_failures: u32,
        last_success: Option<DateTime<Utc>>,
    ) -> OperationalState {
        let mut state = OperationalState::default();
        match source {
            PolledSource::BitcoinCore => {
                state.bitcoin_core = Some(BitcoinCoreState {
                    connected,
                    consecutive_failures,
                    last_attempt: at(300),
                    last_success,
                    snapshot: last_success.map(|observed_at| BitcoinCoreSnapshot {
                        network: BitcoinNetwork::Regtest,
                        block_height: 250,
                        header_height: 250,
                        synchronized: true,
                        observed_at,
                    }),
                });
            }
            PolledSource::Lnd => {
                state.lightning = Some(LightningState {
                    connected,
                    consecutive_failures,
                    last_attempt: at(300),
                    last_success,
                    snapshot: last_success.map(|observed_at| LightningSnapshot {
                        node_id: "02abcdef".into(),
                        synced_to_chain: true,
                        active_channels: 3,
                        inactive_channels: 1,
                        observed_at,
                    }),
                });
            }
        }
        state
    }

    fn evaluate(source: PolledSource, state: &OperationalState) -> crate::DetectorCycle {
        SourcePollFailureDetector::new(source, state)
            .evaluate(
                &InMemoryGraph::new(),
                &DetectorContext {
                    node: Some(source.node_label()),
                    ..DetectorContext::no_context(BitcoinNetwork::Regtest)
                },
            )
            .unwrap()
    }

    #[test]
    fn an_unconfigured_source_yields_an_incomplete_cycle_without_findings() {
        for source in SOURCES {
            let cycle = evaluate(source, &OperationalState::default());
            assert!(cycle.findings.is_empty());
            assert!(!cycle.scope.complete);
        }
    }

    #[test]
    fn a_connected_source_yields_a_complete_cycle_without_findings() {
        for source in SOURCES {
            let cycle = evaluate(source, &state(source, true, 0, Some(at(300))));
            assert!(cycle.findings.is_empty());
            assert!(cycle.scope.complete);
        }
    }

    #[test]
    fn failures_below_the_threshold_neither_raise_nor_count_as_absence() {
        for source in SOURCES {
            for failures in 0..SOURCE_FAILURE_THRESHOLD {
                for last_success in [None, Some(at(0))] {
                    let cycle = evaluate(source, &state(source, false, failures, last_success));
                    assert!(cycle.findings.is_empty(), "{source:?} {failures}");
                    assert!(!cycle.scope.complete, "{source:?} {failures}");
                }
            }
        }
    }

    #[test]
    fn the_threshold_failure_raises_one_finding_with_exact_evidence() {
        for (source, detector, name) in [
            (
                PolledSource::BitcoinCore,
                "bitcoin_core_poll_failure",
                "Bitcoin Core RPC",
            ),
            (PolledSource::Lnd, "lnd_poll_failure", "LND REST"),
        ] {
            let cycle = evaluate(source, &state(source, false, 3, Some(at(0))));
            assert!(cycle.scope.complete);
            assert_eq!(cycle.scope.network, None);
            assert_eq!(cycle.findings.len(), 1);
            let finding = &cycle.findings[0];
            assert_eq!(finding.detector, detector);
            assert_eq!(finding.detector_version, "1");
            assert_eq!(finding.severity, Severity::Warning);
            assert_eq!(finding.node.as_deref(), Some(source.node_label()));
            assert_eq!(finding.channel, None);
            assert_eq!(finding.timestamp, at(300));
            assert_eq!(finding.evidence.len(), 1);
            assert_eq!(finding.evidence[0].key, "source_state");
            assert_eq!(
                finding.evidence[0].value,
                serde_json::json!({
                    "connected": false,
                    "consecutive_failures": 3,
                    "failure_threshold": 3,
                    "last_attempt": at(300),
                    "last_success": at(0),
                    "last_snapshot_observed_at": at(0),
                })
            );
            assert_eq!(
                finding.explanation.as_deref(),
                Some(
                    format!(
                        "The last 3 consecutive {name} polls failed; the last successful poll was at {}. The agent retries on each polling cycle.",
                        at(0).to_rfc3339()
                    )
                    .as_str()
                )
            );
        }
    }

    #[test]
    fn a_source_that_never_connected_is_reported_without_a_last_success() {
        for source in SOURCES {
            let cycle = evaluate(source, &state(source, false, 4, None));
            assert_eq!(cycle.findings.len(), 1);
            let value = &cycle.findings[0].evidence[0].value;
            assert_eq!(value["consecutive_failures"], 4);
            assert_eq!(value["last_success"], serde_json::Value::Null);
            assert_eq!(value["last_snapshot_observed_at"], serde_json::Value::Null);
            assert!(cycle.findings[0]
                .explanation
                .as_deref()
                .unwrap()
                .contains("no successful poll has been recorded"));
        }
    }

    #[test]
    fn identity_is_stable_across_cycles_and_distinct_per_source() {
        let core = |failures| {
            evaluate(
                PolledSource::BitcoinCore,
                &state(PolledSource::BitcoinCore, false, failures, None),
            )
            .findings[0]
                .id
                .clone()
        };
        let lnd = evaluate(PolledSource::Lnd, &state(PolledSource::Lnd, false, 3, None)).findings
            [0]
        .id
        .clone();
        assert_eq!(core(3), core(9));
        assert_ne!(core(3), lnd);
    }

    #[test]
    fn one_source_being_down_does_not_report_the_other() {
        let mut both = state(PolledSource::BitcoinCore, false, 5, None);
        both.lightning = state(PolledSource::Lnd, true, 0, Some(at(300))).lightning;
        assert_eq!(evaluate(PolledSource::BitcoinCore, &both).findings.len(), 1);
        let lnd = evaluate(PolledSource::Lnd, &both);
        assert!(lnd.findings.is_empty());
        assert!(lnd.scope.complete);
    }
}
