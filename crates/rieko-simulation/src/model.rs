//! V2 simulation contracts (ADR-0005).
//!
//! Formal SimulationRequest → SimulationResult lifecycle, machine-readable
//! assumptions/warnings, confidence model, and the SimulationModel trait.
//! These types are protocol-neutral: no LND, SQLite, or API dependencies.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rieko_domain::{Channel, ChannelId};
use rieko_findings::Recommendation;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Lifecycle of a simulation request (D1: stops at Completed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimulationStatus {
    Requested,
    Completed,
    Unsupported,
    InvalidInput,
    Stale,
    Failed,
}

impl SimulationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Completed => "completed",
            Self::Unsupported => "unsupported",
            Self::InvalidInput => "invalid_input",
            Self::Stale => "stale",
            Self::Failed => "failed",
        }
    }
}

/// Model-defined confidence (D8: data completeness, not severity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimulationConfidence {
    High,
    Medium,
    Low,
    Unknown,
}

impl SimulationConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }
}

/// Machine-readable assumption (D10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assumption {
    pub code: String,
    pub description: String,
}

impl Assumption {
    pub fn new(code: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            description: description.into(),
        }
    }
}

/// Machine-readable warning (D10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationWarning {
    pub code: String,
    pub description: String,
}

impl SimulationWarning {
    pub fn new(code: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            description: description.into(),
        }
    }
}

/// Projected channel state baseline or result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectedState {
    pub local_ratio: f64,
    pub local_balance_msat: u64,
    pub remote_balance_msat: u64,
    pub capacity_msat: u64,
}

/// Delta for a single channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectedDelta {
    pub channel_id: String,
    pub local_before_msat: u64,
    pub local_after_msat: u64,
    pub remote_before_msat: u64,
    pub remote_after_msat: u64,
    pub delta_msat: u64,
    pub clears_finding: bool,
}

/// Simulation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationRequest {
    pub id: String,
    pub recommendation_id: String,
    pub finding_id: String,
    pub model_id: String,
    pub model_version: String,
    pub source_observed_at: DateTime<Utc>,
    /// Canonical hash of the immutable source snapshot (channel state)
    /// this simulation was computed against.
    pub source_snapshot_hash: String,
    pub parameters: serde_json::Value,
    pub requested_at: DateTime<Utc>,
}

/// Simulation result (deterministic).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationResult {
    pub simulation_id: String,
    pub status: SimulationStatus,
    pub model_id: String,
    pub model_version: String,
    pub input_hash: String,
    pub baseline: ProjectedState,
    pub projected: ProjectedState,
    pub deltas: Vec<ProjectedDelta>,
    pub assumptions: Vec<Assumption>,
    pub warnings: Vec<SimulationWarning>,
    pub confidence: SimulationConfidence,
    pub calculated_at: DateTime<Utc>,
    pub explanation: Option<String>,
}

/// Immutable context for a simulation model.
pub struct SimulationContext {
    pub channels: HashMap<ChannelId, Channel>,
}

/// Simulation model error.
#[derive(Debug, Error)]
pub enum ModelError {
    #[error("unsupported recommendation type for model {model_id}")]
    Unsupported { model_id: String },
    #[error("invalid parameters: {0}")]
    InvalidInput(String),
    #[error("channel not found: {0}")]
    ChannelNotFound(String),
    #[error("calculation failed: {0}")]
    CalculationFailed(String),
}

/// Simulation model trait (D2: deterministic, versioned).
pub trait SimulationModel {
    fn model_id(&self) -> &str;
    fn model_version(&self) -> &str;

    fn supports(&self, recommendation: &Recommendation) -> bool;

    fn validate(
        &self,
        request: &SimulationRequest,
        context: &SimulationContext,
    ) -> Result<(), ModelError>;

    fn simulate(
        &self,
        request: &SimulationRequest,
        context: &SimulationContext,
    ) -> Result<SimulationResult, ModelError>;
}

/// Compute a deterministic input hash (D2).
pub fn compute_input_hash(
    model_id: &str,
    model_version: &str,
    parameters: &serde_json::Value,
    source_observed_at: &DateTime<Utc>,
    source_snapshot_hash: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"rieko-simulation-v2:");
    h.update(model_id.as_bytes());
    h.update(b":");
    h.update(model_version.as_bytes());
    h.update(b":");
    h.update(source_observed_at.to_rfc3339().as_bytes());
    h.update(b":");
    h.update(source_snapshot_hash.as_bytes());
    h.update(b":");
    h.update(serde_json::to_vec(parameters).unwrap_or_default());
    format!("{:x}", h.finalize())
}

// ── Concrete models ─────────────────────────────────────────────────

/// The first v2 simulation model: "what if I move N msat from channel A
/// to channel B?" Projects local/remote balance changes on both sides
/// using simple arithmetic (no routing, no fees, no network simulation).
#[derive(Default)]
pub struct LiquidityRedistributionModel;

impl LiquidityRedistributionModel {
    pub fn new() -> Self {
        Self
    }
}

impl SimulationModel for LiquidityRedistributionModel {
    fn model_id(&self) -> &str {
        "liquidity-redistribution"
    }

    fn model_version(&self) -> &str {
        "1"
    }

    fn supports(&self, recommendation: &Recommendation) -> bool {
        matches!(
            recommendation.action.action_type,
            rieko_findings::ActionType::RebalanceChannel
        )
    }

    fn validate(
        &self,
        request: &SimulationRequest,
        context: &SimulationContext,
    ) -> Result<(), ModelError> {
        let source_id = request
            .parameters
            .get("source_channel")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ModelError::InvalidInput("source_channel required".into()))?;
        let dest_id = request
            .parameters
            .get("destination_channel")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ModelError::InvalidInput("destination_channel required".into()))?;
        if source_id == dest_id {
            return Err(ModelError::InvalidInput(
                "source and destination must differ".into(),
            ));
        }
        let amount_sats = request
            .parameters
            .get("amount_sats")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ModelError::InvalidInput("amount_sats required".into()))?;
        if amount_sats == 0 {
            return Err(ModelError::InvalidInput("amount must be > 0".into()));
        }
        let src_cid = ChannelId::new(source_id);
        let src = context
            .channels
            .get(&src_cid)
            .ok_or_else(|| ModelError::ChannelNotFound(source_id.into()))?;
        if !src.status.is_open() {
            return Err(ModelError::InvalidInput(format!(
                "source channel {source_id} is not open"
            )));
        }
        if src.capacity_msat == 0 {
            return Err(ModelError::InvalidInput(format!(
                "source channel {source_id} has zero capacity"
            )));
        }
        let dest = context
            .channels
            .get(&ChannelId::new(dest_id))
            .ok_or_else(|| ModelError::ChannelNotFound(dest_id.into()))?;
        let amount_msat = amount_sats.saturating_mul(1000);
        let available = src.liquidity.local_balance_msat;
        if amount_msat > available {
            return Err(ModelError::InvalidInput(format!(
                "amount {amount_sats} sats exceeds available source liquidity {available} msat"
            )));
        }
        if !dest.status.is_open() {
            return Err(ModelError::InvalidInput(format!(
                "destination channel {dest_id} is not open"
            )));
        }
        if dest
            .liquidity
            .local_balance_msat
            .saturating_add(amount_msat)
            > dest.capacity_msat
        {
            return Err(ModelError::InvalidInput(format!(
                "amount {amount_sats} sats would overflow destination channel {dest_id} capacity"
            )));
        }
        Ok(())
    }

    fn simulate(
        &self,
        request: &SimulationRequest,
        context: &SimulationContext,
    ) -> Result<SimulationResult, ModelError> {
        self.validate(request, context)?;

        let source_id = request
            .parameters
            .get("source_channel")
            .and_then(|v| v.as_str())
            .unwrap();
        let dest_id = request
            .parameters
            .get("destination_channel")
            .and_then(|v| v.as_str())
            .unwrap();
        let amount_sats = request
            .parameters
            .get("amount_sats")
            .and_then(|v| v.as_u64())
            .unwrap();
        let amount_msat = amount_sats
            .checked_mul(1000)
            .ok_or_else(|| ModelError::CalculationFailed("amount overflow".into()))?;

        let src = context.channels.get(&ChannelId::new(source_id)).unwrap();
        let dest = context.channels.get(&ChannelId::new(dest_id)).unwrap();

        let src_local_after = src
            .liquidity
            .local_balance_msat
            .checked_sub(amount_msat)
            .ok_or_else(|| ModelError::CalculationFailed("source underflow".into()))?;
        let src_remote_after = src
            .capacity_msat
            .checked_sub(src_local_after)
            .ok_or_else(|| ModelError::CalculationFailed("source capacity underflow".into()))?;
        let dest_local_after = dest
            .liquidity
            .local_balance_msat
            .checked_add(amount_msat)
            .ok_or_else(|| ModelError::CalculationFailed("destination overflow".into()))?;
        let dest_remote_after = dest
            .capacity_msat
            .checked_sub(dest_local_after)
            .ok_or_else(|| ModelError::CalculationFailed("dest capacity underflow".into()))?;

        let src_profile = rieko_domain::LiquidityProfile::compute(
            src.capacity_msat,
            src_local_after,
            src_remote_after,
        );
        let clears_finding = src_profile.imbalance == rieko_domain::LiquidityImbalance::Balanced;

        let now = Utc::now();
        let input_hash = compute_input_hash(
            self.model_id(),
            self.model_version(),
            &request.parameters,
            &request.source_observed_at,
            &request.source_snapshot_hash,
        );

        Ok(SimulationResult {
            simulation_id: request.id.clone(),
            status: SimulationStatus::Completed,
            model_id: self.model_id().into(),
            model_version: self.model_version().into(),
            input_hash,
            baseline: ProjectedState {
                local_ratio: src.liquidity.local_ratio,
                local_balance_msat: src.liquidity.local_balance_msat,
                remote_balance_msat: src.liquidity.remote_balance_msat,
                capacity_msat: src.capacity_msat,
            },
            projected: ProjectedState {
                local_ratio: src_profile.local_ratio,
                local_balance_msat: src_local_after,
                remote_balance_msat: src_remote_after,
                capacity_msat: src.capacity_msat,
            },
            deltas: vec![
                ProjectedDelta {
                    channel_id: source_id.into(),
                    local_before_msat: src.liquidity.local_balance_msat,
                    local_after_msat: src_local_after,
                    remote_before_msat: src.liquidity.remote_balance_msat,
                    remote_after_msat: src_remote_after,
                    delta_msat: amount_msat,
                    clears_finding,
                },
                ProjectedDelta {
                    channel_id: dest_id.into(),
                    local_before_msat: dest.liquidity.local_balance_msat,
                    local_after_msat: dest_local_after,
                    remote_before_msat: dest.liquidity.remote_balance_msat,
                    remote_after_msat: dest_remote_after,
                    delta_msat: amount_msat,
                    clears_finding: false,
                },
            ],
            assumptions: vec![
                Assumption::new(
                    "FeesNotEstimated",
                    "Routing fees are not estimated; actual cost may vary",
                ),
                Assumption::new(
                    "ExternalNetworkStateUnmodelled",
                    "Only local channel state is modelled; network-wide effects are not projected",
                ),
            ],
            warnings: if src.liquidity.local_balance_msat.saturating_sub(amount_msat)
                < src.local_reserve_msat.unwrap_or(0)
            {
                vec![SimulationWarning::new(
                    "ChannelReserveExceeded",
                    "Projected source balance may drop below channel reserve",
                )]
            } else {
                vec![]
            },
            confidence: SimulationConfidence::Medium,
            calculated_at: now,
            explanation: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_hash_is_deterministic() {
        let params = serde_json::json!({"amount_sats": 100_000u64});
        let ts = Utc::now();
        let h1 = compute_input_hash("liquidity-redistribution", "1", &params, &ts, "");
        let h2 = compute_input_hash("liquidity-redistribution", "1", &params, &ts, "");
        assert_eq!(h1, h2);
    }

    #[test]
    fn input_hash_differs_per_model_version() {
        let params = serde_json::json!({});
        let ts = Utc::now();
        let h1 = compute_input_hash("m", "1", &params, &ts, "");
        let h2 = compute_input_hash("m", "2", &params, &ts, "");
        assert_ne!(h1, h2);
    }

    // ── LiquidityRedistributionModel tests ──

    use rieko_domain::{Channel, ChannelId, ChannelStatus, FeePolicy, NodeId};

    fn test_channel(id: &str, capacity: u64, local: u64) -> Channel {
        Channel {
            id: ChannelId::new(id),
            node: NodeId::new("n1"),
            peer: NodeId::new(format!("peer-{id}")),
            channel_point: format!("tx{id}:0"),
            capacity_msat: capacity,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity: rieko_domain::LiquidityProfile::compute(capacity, local, capacity - local),
            last_seen: Utc::now(),
            opening_height: None,
            local_reserve_msat: None,
            remote_reserve_msat: None,
            is_private: false,
            is_initiator: true,
            total_sent_msat: None,
            total_received_msat: None,
        }
    }

    fn test_context(channels: Vec<Channel>) -> SimulationContext {
        SimulationContext {
            channels: channels.into_iter().map(|c| (c.id.clone(), c)).collect(),
        }
    }

    fn test_request(params: serde_json::Value) -> SimulationRequest {
        SimulationRequest {
            id: "sim1".into(),
            recommendation_id: "rec1".into(),
            finding_id: "f1".into(),
            model_id: "liquidity-redistribution".into(),
            model_version: "1".into(),
            source_observed_at: Utc::now(),
            source_snapshot_hash: "hash1".into(),
            parameters: params,
            requested_at: Utc::now(),
        }
    }

    #[test]
    fn valid_redistribution_produces_result() {
        let model = LiquidityRedistributionModel::new();
        let ctx = test_context(vec![
            test_channel("c1", 1_000_000_000, 200_000_000),
            test_channel("c2", 1_000_000_000, 800_000_000),
        ]);
        let req = test_request(serde_json::json!({
            "source_channel": "c1",
            "destination_channel": "c2",
            "amount_sats": 50_000,
        }));
        let result = model.simulate(&req, &ctx).unwrap();
        assert_eq!(result.status, SimulationStatus::Completed);
        assert_eq!(result.deltas.len(), 2);
        assert_eq!(result.deltas[0].channel_id, "c1");
        assert_eq!(result.deltas[0].delta_msat, 50_000_000);
    }

    #[test]
    fn amount_exceeding_source_fails_validation() {
        let model = LiquidityRedistributionModel::new();
        let ctx = test_context(vec![
            test_channel("c1", 1_000_000, 200_000),
            test_channel("c2", 1_000_000, 800_000),
        ]);
        let req = test_request(serde_json::json!({
            "source_channel": "c1",
            "destination_channel": "c2",
            "amount_sats": 300,
        }));
        assert!(model.validate(&req, &ctx).is_err());
    }

    #[test]
    fn invalid_amount_fails_validation() {
        let model = LiquidityRedistributionModel::new();
        let ctx = test_context(vec![
            test_channel("c1", 1_000_000, 500_000),
            test_channel("c2", 1_000_000, 500_000),
        ]);
        let req = test_request(serde_json::json!({
            "source_channel": "c1",
            "destination_channel": "c2",
            "amount_sats": 0,
        }));
        assert!(model.validate(&req, &ctx).is_err());
    }

    #[test]
    fn missing_channel_fails() {
        let model = LiquidityRedistributionModel::new();
        let ctx = test_context(vec![test_channel("c1", 1_000_000, 500_000)]);
        let req = test_request(serde_json::json!({
            "source_channel": "c1",
            "destination_channel": "c2",
            "amount_sats": 100_000,
        }));
        assert!(model.validate(&req, &ctx).is_err());
    }

    #[test]
    fn same_source_and_dest_fails() {
        let model = LiquidityRedistributionModel::new();
        let ctx = test_context(vec![test_channel("c1", 1_000_000, 500_000)]);
        let req = test_request(serde_json::json!({
            "source_channel": "c1",
            "destination_channel": "c1",
            "amount_sats": 100_000,
        }));
        assert!(model.validate(&req, &ctx).is_err());
    }

    #[test]
    fn model_supports_rebalance_recommendation() {
        use rieko_findings::{Action, ActionStage, ActionType, Rationale};
        let model = LiquidityRedistributionModel::new();
        let rec = Recommendation {
            finding_id: "f1".into(),
            action: Action::new(
                ActionType::RebalanceChannel,
                ActionStage::Recommended,
                Some("c1".into()),
                serde_json::json!({}),
                "rebalance",
            ),
            rationale: Rationale {
                evidence: vec![],
                preconditions: vec![],
                expected_effect: "".into(),
                risks: vec![],
                limitations: vec![],
                actionability: rieko_findings::Actionability::OperatorActionable,
            },
        };
        assert!(model.supports(&rec));
    }

    #[test]
    fn model_rejects_unsupported_action() {
        use rieko_findings::{Action, ActionStage, ActionType, Rationale};
        let model = LiquidityRedistributionModel::new();
        let rec = Recommendation {
            finding_id: "f1".into(),
            action: Action::new(
                ActionType::UpdateFeePolicy,
                ActionStage::Recommended,
                Some("c1".into()),
                serde_json::json!({}),
                "fee",
            ),
            rationale: Rationale {
                evidence: vec![],
                preconditions: vec![],
                expected_effect: "".into(),
                risks: vec![],
                limitations: vec![],
                actionability: rieko_findings::Actionability::OperatorActionable,
            },
        };
        assert!(!model.supports(&rec));
    }
}
