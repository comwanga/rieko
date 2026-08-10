use std::collections::HashSet;

use rieko_domain::BitcoinNetwork;
use rieko_findings::{
    finding_identity, Finding, FindingCycleScope, FindingLifecycle, ObservationSource,
    ProducerRole, ProducerVersion,
};
use rieko_graph::{GraphView, HistoryView};
use thiserror::Error;

/// Read-only context handed to a detector. Carries optional history so
/// trend-based detectors can reason over time while staying pure.
pub struct DetectorContext<'a> {
    pub network: BitcoinNetwork,
    pub history: Option<&'a dyn HistoryView>,
    pub source: Option<&'a ObservationSource>,
    pub normalizer: Option<&'a ProducerVersion>,
    pub node: Option<&'a str>,
}

impl<'a> DetectorContext<'a> {
    pub fn no_context(network: BitcoinNetwork) -> Self {
        Self {
            network,
            history: None,
            source: None,
            normalizer: None,
            node: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectorCycle {
    pub scope: FindingCycleScope,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Error)]
pub enum DetectorError {
    #[error("detector evaluation requires a node scope")]
    MissingNodeScope,
    #[error("detector {detector} emitted finding {finding_id} with inconsistent metadata")]
    InvalidFinding {
        detector: String,
        finding_id: String,
    },
    #[error("detector {detector} emitted duplicate finding {finding_id}")]
    DuplicateFinding {
        detector: String,
        finding_id: String,
    },
}

/// A detector consumes a read-only graph snapshot (plus history context) and
/// returns findings. Detectors are pure: no I/O, no LLM calls, no mutation.
pub trait Detector {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn run(&self, view: &dyn GraphView, ctx: &DetectorContext) -> Vec<Finding>;
    fn is_complete(&self, view: &dyn GraphView, ctx: &DetectorContext) -> bool;

    fn evaluate(
        &self,
        view: &dyn GraphView,
        ctx: &DetectorContext,
    ) -> Result<DetectorCycle, DetectorError> {
        let node = ctx.node.ok_or(DetectorError::MissingNodeScope)?;
        let findings = self.run(view, ctx);
        let mut ids = HashSet::new();
        for finding in &findings {
            let expected_id = finding_identity(
                self.id(),
                self.version(),
                Some(ctx.network),
                finding.node.as_deref(),
                finding.channel.as_deref(),
            );
            if finding.detector != self.id()
                || finding.detector_version != self.version()
                || finding.node.as_deref() != Some(node)
                || finding.id != expected_id
                || finding.lifecycle != FindingLifecycle::Active
            {
                return Err(DetectorError::InvalidFinding {
                    detector: self.id().to_string(),
                    finding_id: finding.id.clone(),
                });
            }
            if !ids.insert(finding.id.clone()) {
                return Err(DetectorError::DuplicateFinding {
                    detector: self.id().to_string(),
                    finding_id: finding.id.clone(),
                });
            }
        }
        Ok(DetectorCycle {
            scope: FindingCycleScope {
                detector: self.id().to_string(),
                network: Some(ctx.network),
                node: Some(node.to_string()),
                complete: self.is_complete(view, ctx),
            },
            findings,
        })
    }
}

pub(crate) fn provenance_producers(
    normalizer: Option<&ProducerVersion>,
    detector: &dyn Detector,
) -> Vec<ProducerVersion> {
    let mut producers = normalizer.into_iter().cloned().collect::<Vec<_>>();
    producers.push(ProducerVersion {
        name: detector.id().to_string(),
        version: detector.version().to_string(),
        role: ProducerRole::Detector,
    });
    producers
}
