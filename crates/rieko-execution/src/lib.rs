use rieko_findings::{Action, ActionStage};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("illegal transition {from:?} -> {to:?}")]
    IllegalTransition {
        from: ActionStage,
        to: ActionStage,
    },
    #[error("approval requires a human actor, got `{0}` (the system cannot self-approve)")]
    NeedsHuman(String),
    #[error("action {0} is not in a stage that can be executed")]
    NotExecutable(String),
}

/// The `system` actor reserved for autonomous transitions. Humans must approve
/// every execution (D7: explicit human approval only) — the engine never
/// approves or executes its own recommendations on its own authority.
pub const SYSTEM_ACTOR: &str = "system";

/// Which transitions are legal in the D7 lifecycle:
/// `Recommended -> Simulated -> Approved -> Executed`, plus rejection/failure.
pub fn can_transition(from: ActionStage, to: ActionStage) -> bool {
    use ActionStage::*;
    matches!(
        (from, to),
        (Recommended, Simulated)
            | (Recommended, Approved)
            | (Simulated, Approved)
            | (Approved, Executed)
            | (Recommended, Rejected)
            | (Simulated, Rejected)
            | (Approved, Rejected)
            | (Approved, Failed)
    )
}

/// Promote an action to a later stage. The only stage that does not allow
/// self-service is approval, which requires a non-system human actor.
pub fn transition(action: &Action, to: ActionStage, actor: &str) -> Result<ActionStage, ExecutionError> {
    if !can_transition(action.stage, to) {
        return Err(ExecutionError::IllegalTransition {
            from: action.stage,
            to,
        });
    }
    if to == ActionStage::Approved && actor.trim().is_empty() || to == ActionStage::Approved && actor == SYSTEM_ACTOR {
        return Err(ExecutionError::NeedsHuman(actor.to_string()));
    }
    Ok(to)
}

/// Whether the action may be executed right now (i.e. it has been approved).
pub fn is_executable(action: &Action) -> bool {
    action.stage == ActionStage::Approved
}

/// An executor performs an approved action. The engine ships a read-only,
/// node-agnostic record of execution (`RecordingExecutor`); node-mutating
/// executors (LND rebalance RPC, fee-policy updates) plug in behind this trait
/// without changing the recommendation/approval path.
pub trait Executor {
    /// Perform `action` against a node (or, for the recording executor, log it).
    /// Returns whether it succeeded and a human-readable detail string.
    fn execute(&self, action: &Action) -> Result<ExecutionReport, ExecutionError>;
}

/// Outcome of an executor run, stored in the audit log so approval → execution
/// is fully traceable.
#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub success: bool,
    pub detail: String,
}

impl ExecutionReport {
    pub fn succeeded(detail: impl Into<String>) -> Self {
        Self {
            success: true,
            detail: detail.into(),
        }
    }
}

/// Records an execution without touching a node. Safe default and the basis
/// for tests; a real deployment swaps in an LND-backed executor.
pub struct RecordingExecutor;

impl Executor for RecordingExecutor {
    fn execute(&self, action: &Action) -> Result<ExecutionReport, ExecutionError> {
        if !is_executable(action) {
            return Err(ExecutionError::NotExecutable(action.id.clone()));
        }
        Ok(ExecutionReport::succeeded(format!(
            "recorded execution of {} on {}",
            action.action_type.as_str(),
            action.target.as_deref().unwrap_or("(node)")
        )))
    }
}

#[cfg(test)]
mod tests {
    use rieko_findings::{Action, ActionStage, ActionType};

    use super::*;

    fn action(stage: ActionStage) -> Action {
        Action::new(
            ActionType::RebalanceChannel,
            stage,
            Some("c1".into()),
            serde_json::json!({"desired_ratio": 0.5}),
            "rebalance c1",
        )
    }

    #[test]
    fn recommend_to_simulate_to_approve_is_legal() {
        let rec = action(ActionStage::Recommended);
        assert_eq!(
            transition(&rec, ActionStage::Simulated, SYSTEM_ACTOR).unwrap(),
            ActionStage::Simulated
        );
        let sim = Action {
            stage: ActionStage::Simulated,
            ..rec
        };
        assert_eq!(
            transition(&sim, ActionStage::Approved, "alice").unwrap(),
            ActionStage::Approved
        );
    }

    #[test]
    fn system_cannot_approve_its_own_work() {
        let rec = action(ActionStage::Simulated);
        assert!(matches!(
            transition(&rec, ActionStage::Approved, SYSTEM_ACTOR),
            Err(ExecutionError::NeedsHuman(_))
        ));
    }

    #[test]
    fn empty_actor_cannot_approve() {
        let rec = action(ActionStage::Simulated);
        assert!(matches!(
            transition(&rec, ActionStage::Approved, ""),
            Err(ExecutionError::NeedsHuman(_))
        ));
    }

    #[test]
    fn cannot_skip_steps() {
        let rec = action(ActionStage::Recommended);
        assert!(matches!(
            transition(&rec, ActionStage::Executed, "alice"),
            Err(ExecutionError::IllegalTransition { .. })
        ));
    }

    #[test]
    fn rejection_is_always_legal_from_active_stages() {
        for stage in [ActionStage::Recommended, ActionStage::Simulated, ActionStage::Approved] {
            let a = action(stage);
            assert_eq!(transition(&a, ActionStage::Rejected, "alice").unwrap(), ActionStage::Rejected);
        }
    }

    #[test]
    fn recording_executor_requires_approval() {
        let exec = RecordingExecutor;
        let rec = action(ActionStage::Approved);
        assert!(exec.execute(&rec).is_ok());
        let not_approved = action(ActionStage::Simulated);
        assert!(matches!(
            exec.execute(&not_approved),
            Err(ExecutionError::NotExecutable(_))
        ));
    }
}