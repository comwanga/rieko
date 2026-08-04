use rieko_findings::Finding;
use rieko_graph::GraphView;

/// A detector consumes a read-only graph snapshot and returns findings.
/// Detectors are pure: no I/O, no LLM calls, no mutation.
pub trait Detector {
    fn id(&self) -> &'static str;
    fn run(&self, view: &dyn GraphView) -> Vec<Finding>;
}
