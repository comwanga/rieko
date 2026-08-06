use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::action_identity;

/// Lifecycle of a recommended action (D7). v1 only ever reaches `Recommended`;
/// later milestones add Simulated / Approved / Executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionStage {
    Recommended,
    Simulated,
    Approved,
    Executed,
    Rejected,
    Failed,
}

/// The kinds of actions Rieko can recommend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    RebalanceChannel,
    UpdateFeePolicy,
    RestartService,
    Custom,
}

impl ActionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RebalanceChannel => "rebalance_channel",
            Self::UpdateFeePolicy => "update_fee_policy",
            Self::RestartService => "restart_service",
            Self::Custom => "custom",
        }
    }
}

/// A concrete, typed action with parameters. v1 produces only
/// `Recommended` actions; every action is appended to the audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub action_type: ActionType,
    pub stage: ActionStage,
    /// Free-form target, e.g. a channel id or service name.
    pub target: Option<String>,
    pub params: serde_json::Value,
    pub summary: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Action {
    pub fn new(
        action_type: ActionType,
        stage: ActionStage,
        target: Option<String>,
        params: serde_json::Value,
        summary: impl Into<String>,
    ) -> Self {
        Self::with_default(
            Uuid::new_v4().to_string(),
            action_type,
            stage,
            target,
            params,
            summary,
        )
    }

    /// Construct an action whose id is deterministically derived from its
    /// source finding and action kind, so re-persisting the same recommendation
    /// over many runs yields the same row (RIEKO-AUDIT-002).
    pub fn for_recommendation(
        finding_id: &str,
        action_type: ActionType,
        target: Option<String>,
        params: serde_json::Value,
        summary: impl Into<String>,
    ) -> Self {
        let id = action_identity(finding_id, action_type, target.as_deref());
        Self::with_default(
            id,
            action_type,
            ActionStage::Recommended,
            target,
            params,
            summary,
        )
    }

    fn with_default(
        id: String,
        action_type: ActionType,
        stage: ActionStage,
        target: Option<String>,
        params: serde_json::Value,
        summary: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            action_type,
            stage,
            target,
            params,
            summary: summary.into(),
            created_at: now,
            updated_at: now,
        }
    }
}

/// A recommendation ties a finding to a proposed action, together with the
/// evidence-backed reasoning that justifies it (RIEKO-AUDIT-010).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    pub finding_id: String,
    pub action: Action,
    /// Structured, evidence-backed reasoning. Filled deterministically by the
    /// engine — never by an LLM — and always present.
    pub rationale: Rationale,
}

/// Whether a recommendation asks the operator to act or merely informs them.
/// Neither grants Rieko any authority to execute the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Actionability {
    /// Observe / understand. No operator action is being proposed.
    #[default]
    Informational,
    /// A human operator may choose to act; it is a decision-support suggestion.
    OperatorActionable,
}

impl Actionability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::OperatorActionable => "operator_actionable",
        }
    }
}

/// The evidence-backed reasoning behind a recommendation. Deterministic,
/// populated by the engine from the source finding (RIEKO-AUDIT-010). An LLM
/// is never required, and can never change these fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rationale {
    /// The evidence keys (and, where useful, values) from the finding that the
    /// advice is grounded in.
    pub evidence: Vec<String>,
    /// Conditions that should hold before an operator considers acting.
    pub preconditions: Vec<String>,
    /// The expected operational effect if the operator elects to act.
    pub expected_effect: String,
    /// Risks or trade-offs the operator should weigh.
    pub risks: Vec<String>,
    /// Known limitations or uncertainty of the analysis.
    pub limitations: Vec<String>,
    /// Whether this is informational context or operator-actionable advice.
    pub actionability: Actionability,
}

impl Default for Rationale {
    fn default() -> Self {
        Self {
            evidence: Vec::new(),
            preconditions: Vec::new(),
            expected_effect: String::new(),
            risks: Vec::new(),
            limitations: Vec::new(),
            actionability: Actionability::Informational,
        }
    }
}

/// One row of the append-only audit log. Written for every action, including
/// read-only recommendations (D7). Records the state transition that actually
/// happened: `previous_stage` -> `stage`, or `None` when the object was just
/// created (RIEKO-AUDIT-007).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub action_id: String,
    pub action_type: ActionType,
    /// State the object was in before this entry, if any.
    pub previous_stage: Option<ActionStage>,
    /// State the object is in after this entry.
    pub stage: ActionStage,
    /// Who/what triggered this: `system` or a human actor id.
    pub actor: String,
    pub details: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

impl AuditEntry {
    /// An audit entry for the creation of `action` (no previous state).
    pub fn from_action(
        action: &Action,
        actor: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            action_id: action.id.clone(),
            action_type: action.action_type,
            previous_stage: None,
            stage: action.stage,
            actor: actor.into(),
            details,
            timestamp: Utc::now(),
        }
    }

    /// An audit entry for a real transition `from` -> `action.stage`.
    pub fn from_transition(
        action: &Action,
        from: ActionStage,
        actor: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            action_id: action.id.clone(),
            action_type: action.action_type,
            previous_stage: Some(from),
            stage: action.stage,
            actor: actor.into(),
            details,
            timestamp: Utc::now(),
        }
    }
}
