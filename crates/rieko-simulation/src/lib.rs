//! What-if simulation of recommended actions (D7 Simulate).
//!
//! **V2** (ADR-0005): simulation is now a first-class, default-enabled feature
//! with a formal `SimulationRequest → SimulationResult` lifecycle, deterministic
//! identity via `input_hash`, machine-readable assumptions and warnings, and a
//! confidence model. The projections remain pure functions — no LND/network I/O.
//!
//! The crate must never depend on `rieko-execution`, `rieko-api`, `rieko-cli`,
//! `rieko-llm`, `rieko-alerts`, or any LND HTTP client.

use std::collections::HashMap;

pub mod model;

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

    /// Project how rebalancing `source_channel` to `desired_ratio` would
    /// affect every hop in the `route`. The route is an ordered list of
    /// channel IDs from source to destination (produced by a path-finding
    /// algorithm like Dijkstra in `rieko-graph`).
    ///
    /// Returns one `Simulation` per channel in the route. The source channel
    /// gets the projected ratio shift; intermediate hops reflect the amount
    /// moving through them (same delta, opposite direction per hop).
    ///
    /// `channels` is a lookup from ChannelId → Channel for the full graph.
    pub fn project_rebalance_route(
        &self,
        source_channel: &Channel,
        desired_ratio: f64,
        route: &[ChannelId],
        channels: &HashMap<ChannelId, Channel>,
        finding_id: &str,
    ) -> Result<Vec<Simulation>, SimulationError> {
        if route.is_empty() {
            return Err(SimulationError::UnsupportedActionType("empty route".into()));
        }
        if source_channel.capacity_msat == 0 {
            return Err(SimulationError::ZeroCapacity(source_channel.id.to_string()));
        }
        let desired = desired_ratio.clamp(0.0, 1.0);
        let local_after = (desired * source_channel.capacity_msat as f64).round() as u64;
        let delta = local_after.abs_diff(source_channel.liquidity.local_balance_msat);

        let mut simulations = Vec::with_capacity(route.len());

        for (i, cid) in route.iter().enumerate() {
            let hop = channels
                .get(cid)
                .ok_or_else(|| SimulationError::ChannelNotFound(cid.clone()))?;

            let (local_after, remote_after) = if i == 0 {
                // Source channel: rebalance to target ratio.
                let la = (desired * hop.capacity_msat as f64).round() as u64;
                let ra = hop.capacity_msat.saturating_sub(la);
                (la, ra)
            } else {
                // Intermediate hop: same delta moves through, direction
                // alternates per hop (inbound/outbound swap).
                let direction = if i % 2 == 0 { delta } else { 0 };
                let local_after = if direction > 0 {
                    hop.liquidity.local_balance_msat.saturating_sub(delta)
                } else {
                    hop.liquidity.local_balance_msat.saturating_add(delta)
                };
                let remote_after = hop.capacity_msat.saturating_sub(local_after);
                (local_after, remote_after)
            };

            let projected = LiquidityProfile::compute(hop.capacity_msat, local_after, remote_after);
            let clears_finding = projected.imbalance == LiquidityImbalance::Balanced;

            simulations.push(Simulation {
                id: uuid::Uuid::new_v4().to_string(),
                action_id: format!("route-{finding_id}"),
                finding_id: finding_id.to_string(),
                action_type: ActionType::RebalanceChannel,
                projection: SimulationProjection {
                    local_ratio_before: hop.liquidity.local_ratio,
                    local_ratio_after: projected.local_ratio,
                    local_balance_msat_after: local_after,
                    remote_balance_msat_after: remote_after,
                    delta_msat: delta,
                    clears_finding,
                    summary: format!(
                        "Hop {i} ({cid}): {delta} msat routed → local={local_after}, {status}",
                        status = if clears_finding {
                            "balanced"
                        } else {
                            "still unbalanced"
                        },
                    ),
                },
                created_at: chrono::Utc::now(),
            });
        }

        Ok(simulations)
    }

    /// Project where a channel's ratio would be after `cycles_ahead` cycles
    /// of steady decline at `decline_per_cycle` per cycle. Returns `None` if
    /// the current ratio is already at zero or capacity is invalid.
    pub fn project_drift(
        channel: &Channel,
        decline_per_cycle: f64,
        cycles_ahead: u32,
    ) -> Option<SimulationProjection> {
        if channel.capacity_msat == 0 || channel.liquidity.local_ratio <= 0.0 {
            return None;
        }
        let projected_ratio =
            (channel.liquidity.local_ratio - decline_per_cycle * cycles_ahead as f64).max(0.0);
        let local_after = (projected_ratio * channel.capacity_msat as f64).round() as u64;
        let remote_after = channel.capacity_msat.saturating_sub(local_after);
        let projected = LiquidityProfile::compute(channel.capacity_msat, local_after, remote_after);
        let will_be_critical = projected.imbalance == LiquidityImbalance::SeverelyDrained;

        Some(SimulationProjection {
            local_ratio_before: channel.liquidity.local_ratio,
            local_ratio_after: projected_ratio,
            local_balance_msat_after: local_after,
            remote_balance_msat_after: remote_after,
            delta_msat: local_after.abs_diff(channel.liquidity.local_balance_msat),
            clears_finding: false,
            summary: format!(
                "After {cycles_ahead} cycles at -{:.4} per cycle, channel {} would \
                 reach local_ratio={:.4} ({}) — the current severity threshold is \
                 crossed in {} cycle(s).",
                decline_per_cycle,
                channel.id,
                projected_ratio,
                if will_be_critical {
                    "Critical"
                } else if projected.local_ratio < 0.10 {
                    "Drained"
                } else {
                    "Stable"
                },
                ((channel.liquidity.local_ratio - 0.10).max(0.0) / decline_per_cycle) as u32,
            ),
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
            channel_point: "tx:0".into(),
            local_reserve_msat: None,
            remote_reserve_msat: None,
            is_private: false,
            is_initiator: true,
            total_sent_msat: None,
            total_received_msat: None,
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

    // ── Multi-hop rebalance route ────────────────────────────────────

    fn graph_map(channels: &[Channel]) -> HashMap<ChannelId, Channel> {
        channels.iter().map(|c| (c.id.clone(), c.clone())).collect()
    }

    #[test]
    #[allow(clippy::cloned_ref_to_slice_refs)]
    fn single_hop_route_is_equivalent_to_direct_rebalance() {
        let c = channel("c1", 10_000, 90_000);
        let channels = graph_map(&[c.clone()]);
        let route = vec![ChannelId::new("c1")];
        let sims = Simulator
            .project_rebalance_route(&c, 0.5, &route, &channels, "f1")
            .unwrap();
        assert_eq!(sims.len(), 1);
        assert!(sims[0].projection.clears_finding);
        assert_eq!(sims[0].projection.delta_msat, 40_000);
    }

    #[test]
    fn multi_hop_projects_effect_on_each_hop() {
        let c1 = channel("c1", 10_000, 90_000);
        let c2 = channel("c2", 500_000, 500_000);
        let channels = graph_map(&[c1.clone(), c2.clone()]);
        let route = vec![ChannelId::new("c1"), ChannelId::new("c2")];
        let sims = Simulator
            .project_rebalance_route(&c1, 0.5, &route, &channels, "f1")
            .unwrap();
        assert_eq!(sims.len(), 2);
        assert!(sims[0].projection.clears_finding); // c1 balanced
                                                    // c2 gets delta applied (intermediate hop)
        assert_eq!(sims[1].projection.delta_msat, 40_000);
    }

    #[test]
    fn empty_route_is_error() {
        let c = channel("c1", 50_000, 50_000);
        let channels = graph_map(&[]);
        assert!(Simulator
            .project_rebalance_route(&c, 0.5, &[], &channels, "f1")
            .is_err());
    }

    // ── Time-bound drift projection ──────────────────────────────────

    #[test]
    fn drift_projection_shows_decline_after_cycles() {
        let c = channel("c1", 400_000, 600_000); // local_ratio = 0.4
        let proj = Simulator::project_drift(&c, 0.05, 4).unwrap();
        // 0.4 - 0.05*4 = 0.2
        assert!((proj.local_ratio_after - 0.2).abs() < 1e-9);
        assert_eq!(proj.delta_msat, 200_000);
    }

    #[test]
    fn drift_projection_floors_at_zero() {
        let c = channel("c1", 100_000, 900_000); // local_ratio = 0.1
        let proj = Simulator::project_drift(&c, 0.05, 5).unwrap();
        assert_eq!(proj.local_ratio_after, 0.0);
    }

    #[test]
    fn drift_projection_none_for_zero_capacity() {
        let mut c = channel("c1", 0, 0);
        c.capacity_msat = 0;
        assert!(Simulator::project_drift(&c, 0.05, 3).is_none());
    }
}
