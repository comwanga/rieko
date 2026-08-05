use rieko_findings::Finding;
use rieko_graph::{GraphView, HistoryView};

/// Read-only context handed to a detector. Carries optional history so
/// trend-based detectors can reason over time while staying pure.
pub struct DetectorContext<'a> {
    pub history: Option<&'a dyn HistoryView>,
}

impl<'a> DetectorContext<'a> {
    pub fn no_context() -> Self {
        Self { history: None }
    }
}

/// A detector consumes a read-only graph snapshot (plus history context) and
/// returns findings. Detectors are pure: no I/O, no LLM calls, no mutation.
pub trait Detector {
    fn id(&self) -> &'static str;
    /// Detector version, part of the stable finding identity. Bump when the
    /// detection semantics change so re-runs produce fresh identities.
    fn version(&self) -> &'static str {
        "1"
    }
    fn run(&self, view: &dyn GraphView, ctx: &DetectorContext) -> Vec<Finding>;
}
