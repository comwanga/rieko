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
    h.update(serde_json::to_vec(parameters).unwrap_or_default());
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_hash_is_deterministic() {
        let params = serde_json::json!({"amount_sats": 100_000u64});
        let ts = Utc::now();
        let h1 = compute_input_hash("liquidity-redistribution", "1", &params, &ts);
        let h2 = compute_input_hash("liquidity-redistribution", "1", &params, &ts);
        assert_eq!(h1, h2);
    }

    #[test]
    fn input_hash_differs_per_model_version() {
        let params = serde_json::json!({});
        let ts = Utc::now();
        let h1 = compute_input_hash("m", "1", &params, &ts);
        let h2 = compute_input_hash("m", "2", &params, &ts);
        assert_ne!(h1, h2);
    }
}
