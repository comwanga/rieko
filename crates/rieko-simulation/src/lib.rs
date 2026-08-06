//! What-if simulation of recommended actions (D7 Simulate).
//!
//! This crate is **future-facing and deliberately isolated from the v1
//! product** (RIEKO-AUDIT-022): the default build never links it, and it is
//! only pulled in through the `future` feature of `rieko-cli`.
//!
//! The projections are pure functions over explicit inputs (a [`Channel`], an
//! [`Action`], a finding id). They never ingest, never detect, never persist
//! findings, and never append audit transitions — callers decide persistence.
//! The crate has no storage, SQLite, or LND dependencies, so its tests stay
//! independent of any database or live node.

use rieko_domain::{Channel, ChannelId, LiquidityImbalance, LiquidityProfile};
use rieko_findings::{Action, ActionType, Simulation, SimulationProjection};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SimulationError {
    #[error("cannot simulate action for channel {0}: not found in graph")]
    ChannelNotFound(ChannelId),
    #[error("cannot simulate {0}: no desired ratio in params")]
    MissingDesiredRatio(String),
    #[error("cannot simulate action type {0}")]
    UnsupportedActionType(String),
    #[error("cannot simulate: channel {0} has zero capacity")]
    ZeroCapacity(String),
}

/// Runs what-if projections of recommended actions (D7 Simulate stage).
/// Simulations are deterministic: they read the current channel, apply the
/// action's intended target, and project the resulting liquidity state. They
/// never touch the node — execution is a later, human-approved milestone.
pub struct Simulator;

impl Simulator {
    /// Project what `action` would do to `channel`. Requires a channel lookup;
    /// callers resolve from graph by `action.target`.
    pub fn project(
        &self,
        channel: &Channel,
        action: &Action,
        finding_id: &str,
    ) -> Result<Simulation, SimulationError> {
        let projection = match action.action_type {
            ActionType::RebalanceChannel => self.project_rebalance(channel, action)?,
            ActionType::UpdateFeePolicy => {
                // Fee changes do not move liquidity; the projection is a no-op
                // on balances and never clears a *liquidity* finding outright.
                SimulationProjection {
                    local_ratio_before: channel.liquidity.local_ratio,
                    local_ratio_after: channel.liquidity.local_ratio,
                    local_balance_msat_after: channel.liquidity.local_balance_msat,
                    remote_balance_msat_after: channel.liquidity.remote_balance_msat,
                    delta_msat: 0,
                    clears_finding: false,
                    summary: "Fee policy changes do not move existing liquidity; the imbalance remains until flows shift".into(),
                }
            }
            ActionType::RestartService | ActionType::Custom => {
                return Err(SimulationError::UnsupportedActionType(
                    action.action_type.as_str().into(),
                ))
            }
        };

        Ok(Simulation {
            id: uuid::Uuid::new_v4().to_string(),
            action_id: action.id.clone(),
            finding_id: finding_id.to_string(),
            action_type: action.action_type,
            projection,
            created_at: chrono::Utc::now(),
        })
    }

    fn project_rebalance(
        &self,
        channel: &Channel,
        action: &Action,
    ) -> Result<SimulationProjection, SimulationError> {
        if channel.capacity_msat == 0 {
            return Err(SimulationError::ZeroCapacity(channel.id.to_string()));
        }
        let desired: Option<f64> = action.params.get("desired_ratio").and_then(|v| v.as_f64());
        let Some(desired) = desired else {
            // RIEKO-AUDIT-010: conservative rebalance reviews carry no numeric
            // target. Project the honest consequence — no liquidity movement —
            // rather than inventing a target ratio.
            return Ok(SimulationProjection {
                local_ratio_before: channel.liquidity.local_ratio,
                local_ratio_after: channel.liquidity.local_ratio,
                local_balance_msat_after: channel.liquidity.local_balance_msat,
                remote_balance_msat_after: channel.liquidity.remote_balance_msat,
                delta_msat: 0,
                clears_finding: false,
                summary: format!(
                    "Channel {} rebalance review carries no numeric target; no liquidity movement is projected.",
                    channel.id
                ),
            });
        };
        let desired = desired.clamp(0.0, 1.0);

        let local_after = (desired * channel.capacity_msat as f64).round() as u64;
        let remote_after = channel.capacity_msat.saturating_sub(local_after);
        let before_local = channel.liquidity.local_balance_msat;

        let projected = LiquidityProfile::compute(channel.capacity_msat, local_after, remote_after);
        let clears_finding = projected.imbalance == LiquidityImbalance::Balanced;

        Ok(SimulationProjection {
            local_ratio_before: channel.liquidity.local_ratio,
            local_ratio_after: projected.local_ratio,
            local_balance_msat_after: local_after,
            remote_balance_msat_after: remote_after,
            delta_msat: local_after.abs_diff(before_local),
            clears_finding,
            summary: format!(
                "Rebalancing {} to a {:.0}% local ratio moves {} msat, leaving the channel {}.",
                channel.id,
                desired * 100.0,
                local_after.abs_diff(before_local),
                if clears_finding {
                    "balanced"
                } else {
                    "still unbalanced"
                },
            ),
        })
    }
}
#[cfg(test)]
mod tests {
    use rieko_domain::{Channel, ChannelId, ChannelStatus, FeePolicy, LiquidityProfile, NodeId};
    use rieko_findings::{Action, ActionStage, ActionType};

    use super::*;

    fn channel(id: &str, local: u64, remote: u64) -> Channel {
        let capacity = local + remote;
        Channel {
            id: ChannelId::new(id),
            node: NodeId::new("local-node"),
            peer: NodeId::new(format!("peer-{id}")),
            capacity_msat: capacity,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity: LiquidityProfile::compute(capacity, local, remote),
            last_seen: chrono::Utc::now(),
            opening_height: Some(1),
        }
    }

    fn rebalance_action(target: &str, desired: f64) -> Action {
        Action::new(
            ActionType::RebalanceChannel,
            ActionStage::Recommended,
            Some(target.into()),
            serde_json::json!({ "desired_ratio": desired }),
            "rebalance",
        )
    }

    #[test]
    fn rebalance_to_half_clears_drained_channel() {
        let c = channel("c1", 10_000, 90_000);
        let sim = Simulator
            .project(&c, &rebalance_action("c1", 0.5), "f1")
            .unwrap();
        assert!(sim.projection.clears_finding);
        assert!((sim.projection.local_ratio_after - 0.5).abs() < 1e-9);
        assert_eq!(sim.projection.delta_msat, 40_000);
        assert_eq!(sim.projection.local_balance_msat_after, 50_000);
    }

    #[test]
    fn rebalance_delta_is_absolute_motion() {
        let c = channel("c1", 90_000, 10_000);
        let sim = Simulator
            .project(&c, &rebalance_action("c1", 0.5), "f1")
            .unwrap();
        assert_eq!(sim.projection.delta_msat, 40_000);
        assert_eq!(sim.projection.local_balance_msat_after, 50_000);
    }

    #[test]
    fn fee_policy_never_clears_liquidity_finding() {
        let c = channel("c1", 10_000, 90_000);
        let action = Action::new(
            ActionType::UpdateFeePolicy,
            ActionStage::Recommended,
            Some("c1".into()),
            serde_json::json!({}),
            "lower fees",
        );
        let sim = Simulator.project(&c, &action, "f1").unwrap();
        assert!(!sim.projection.clears_finding);
        assert_eq!(sim.projection.delta_msat, 0);
        assert_eq!(sim.projection.local_ratio_after, c.liquidity.local_ratio);
    }

    #[test]
    fn unsupported_action_type_is_rejected() {
        let c = channel("c1", 50_000, 50_000);
        let action = Action::new(
            ActionType::RestartService,
            ActionStage::Recommended,
            None,
            serde_json::json!({}),
            "restart",
        );
        assert!(Simulator.project(&c, &action, "f1").is_err());
    }

    #[test]
    fn zero_capacity_is_rejected() {
        let mut c = channel("c1", 0, 0);
        c.capacity_msat = 0;
        assert!(Simulator
            .project(&c, &rebalance_action("c1", 0.5), "f1")
            .is_err());
    }

    #[test]
    fn rebalance_review_without_numeric_target_projects_no_movement() {
        // RIEKO-AUDIT-010: conservative rebalance reviews carry no `desired_ratio`.
        // Projecting them must not invent a target — the honest projection is no
        // liquidity movement, and the imbalance is not cleared.
        let c = channel("c1", 10_000, 90_000);
        let action = Action::new(
            ActionType::RebalanceChannel,
            ActionStage::Recommended,
            Some("c1".into()),
            serde_json::json!({ "reason": "outbound liquidity drained" }),
            "Review the intended role of channel c1 before considering a rebalance.",
        );
        let sim = Simulator.project(&c, &action, "f1").unwrap();
        assert!(!sim.projection.clears_finding);
        assert_eq!(sim.projection.delta_msat, 0);
        assert_eq!(sim.projection.local_ratio_after, c.liquidity.local_ratio);
        assert_eq!(
            sim.projection.local_balance_msat_after,
            c.liquidity.local_balance_msat
        );
    }
}
