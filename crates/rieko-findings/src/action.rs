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

/// A recommendation ties a finding to a proposed action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    pub finding_id: String,
    pub action: Action,
}

/// One row of the immutable audit log. Written for every action, including
/// read-only recommendations (D7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub action_id: String,
    pub action_type: ActionType,
    pub stage: ActionStage,
    /// Who/what triggered this: `system` or a human actor id.
    pub actor: String,
    pub details: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

impl AuditEntry {
    pub fn from_action(
        action: &Action,
        actor: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            action_id: action.id.clone(),
            action_type: action.action_type,
            stage: action.stage,
            actor: actor.into(),
            details,
            timestamp: Utc::now(),
        }
    }
}
