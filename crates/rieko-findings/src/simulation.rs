use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::action::ActionType;

/// A what-if projection of a channel if an action were applied. The
/// simulator (rieko-simulation) computes these; they answer "if we rebalance
/// to target ratio X, does the finding clear and what does the balance look
/// like?" before anything touches the node (D7: Recommend → Simulate).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationProjection {
    pub local_ratio_before: f64,
    pub local_ratio_after: f64,
    pub local_balance_msat_after: u64,
    pub remote_balance_msat_after: u64,
    /// Motion required to reach the projection, in msat (0 for no-op).
    pub delta_msat: u64,
    /// True when the projected end state is balanced (the motivating finding
    /// would clear).
    pub clears_finding: bool,
    /// Plain-language account of what the projection means.
    pub summary: String,
}

/// One recorded what-if run. Tied to a recommended action via `action_id`.
/// Persisted durably so an operator can review the reasoning behind an
/// approval later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Simulation {
    pub id: String,
    pub action_id: String,
    pub finding_id: String,
    pub action_type: ActionType,
    pub projection: SimulationProjection,
    pub created_at: DateTime<Utc>,
}
