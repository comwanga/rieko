//! V2 deterministic simulation contracts (ADR-0005).
//!
//! A canonical input embeds the exact persisted channel snapshots used by the
//! model. Run identity and timestamps remain outside the deterministic output.

use chrono::{DateTime, Duration, Utc};
use rieko_domain::{ChannelSnapshot, ChannelStatus};
use rieko_findings::{ActionType, FindingProvenance, Recommendation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_FRESHNESS: Duration = Duration::minutes(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationStatus {
    Requested,
    Completed,
    Unsupported,
    InvalidInput,
    Stale,
    Failed,
}

impl SimulationStatus {
    pub fn as_str(self) -> &'static str {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationConfidence {
    High,
    Medium,
    Low,
    Unknown,
}

impl SimulationConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationNoticeSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assumption {
    pub code: String,
    pub description: String,
    pub severity: SimulationNoticeSeverity,
}

impl Assumption {
    pub fn new(code: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            description: description.into(),
            severity: SimulationNoticeSeverity::Info,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationWarning {
    pub code: String,
    pub description: String,
    pub severity: SimulationNoticeSeverity,
}

impl SimulationWarning {
    pub fn new(code: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            description: description.into(),
            severity: SimulationNoticeSeverity::Warning,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectedState {
    pub local_ratio: f64,
    pub local_balance_msat: u64,
    pub remote_balance_msat: u64,
    pub capacity_msat: u64,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityRedistributionParameters {
    pub source_channel: String,
    pub destination_channel: String,
    pub amount_msat: u64,
}

/// Canonical, replayable model input. Every calculation-affecting source value
/// is embedded so snapshot retention cannot change or destroy a historical run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationInput {
    pub recommendation_id: String,
    pub recommendation_target: String,
    pub finding_id: String,
    pub finding_channel: String,
    pub node_id: String,
    pub provenance: FindingProvenance,
    pub action_type: ActionType,
    pub model_id: String,
    pub model_version: String,
    pub parameters: LiquidityRedistributionParameters,
    pub source_snapshot: ChannelSnapshot,
    pub destination_snapshot: ChannelSnapshot,
}

impl SimulationInput {
    pub fn observed_at(&self) -> DateTime<Utc> {
        self.source_snapshot.ts
    }

    pub fn is_stale_at(&self, now: DateTime<Utc>, freshness: Duration) -> bool {
        now.signed_duration_since(self.observed_at()) > freshness
    }

    pub fn is_future_at(&self, now: DateTime<Utc>) -> bool {
        self.observed_at() > now
    }
}

/// Per-request metadata. It is deliberately excluded from the input hash and
/// deterministic result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationRequest {
    pub id: String,
    pub input: SimulationInput,
    pub requested_at: DateTime<Utc>,
}

/// Pure deterministic output. It contains no run ID, wall-clock timestamp, or
/// LLM explanation, so equal canonical inputs produce equal serialized output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationResult {
    pub model_id: String,
    pub model_version: String,
    pub input_hash: String,
    pub baseline: ProjectedState,
    pub projected: ProjectedState,
    pub deltas: Vec<ProjectedDelta>,
    pub assumptions: Vec<Assumption>,
    pub warnings: Vec<SimulationWarning>,
    pub confidence: SimulationConfidence,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("unsupported recommendation type for model {model_id}")]
    Unsupported { model_id: String },
    #[error("invalid parameters: {0}")]
    InvalidInput(String),
    #[error("calculation failed: {0}")]
    CalculationFailed(String),
    #[error("canonical input serialization failed: {0}")]
    Serialization(String),
}

pub trait SimulationModel {
    fn model_id(&self) -> &str;
    fn model_version(&self) -> &str;
    fn supports(&self, recommendation: &Recommendation) -> bool;
    fn validate(&self, input: &SimulationInput) -> Result<(), ModelError>;
    fn simulate(&self, input: &SimulationInput) -> Result<SimulationResult, ModelError>;
}

pub fn compute_input_hash(input: &SimulationInput) -> Result<String, ModelError> {
    use sha2::{Digest, Sha256};

    let canonical_value = serde_json::to_value(input).map_err(|error| {
        ModelError::Serialization(format!("serializing canonical simulation input: {error}"))
    })?;
    let canonical = serde_json::to_vec(&canonical_value).map_err(|error| {
        ModelError::Serialization(format!("encoding canonical simulation input: {error}"))
    })?;
    let mut hash = Sha256::new();
    hash.update(b"rieko-simulation-input-v3");
    hash.update((canonical.len() as u64).to_be_bytes());
    hash.update(canonical);
    Ok(format!("{:x}", hash.finalize()))
}

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
        "2"
    }

    fn supports(&self, recommendation: &Recommendation) -> bool {
        recommendation.action.action_type == ActionType::RebalanceChannel
    }

    fn validate(&self, input: &SimulationInput) -> Result<(), ModelError> {
        if input.action_type != ActionType::RebalanceChannel {
            return Err(ModelError::Unsupported {
                model_id: self.model_id().into(),
            });
        }
        if input.node_id.trim().is_empty() {
            return Err(ModelError::InvalidInput("node identity is required".into()));
        }
        if let rieko_findings::ObservationSource::Lnd {
            configured_node, ..
        } = &input.provenance.source
        {
            if configured_node != &input.node_id {
                return Err(ModelError::InvalidInput(
                    "source provenance does not match node identity".into(),
                ));
            }
        }
        if input.model_id != self.model_id() || input.model_version != self.model_version() {
            return Err(ModelError::InvalidInput(format!(
                "request declares model {} v{}, expected {} v{}",
                input.model_id,
                input.model_version,
                self.model_id(),
                self.model_version()
            )));
        }
        let parameters = &input.parameters;
        let (provenance_channel, provenance_observed_at) = match &input.provenance.observation {
            rieko_findings::ObservationReference::ChannelState {
                channel_id,
                snapshot,
            } => (channel_id, snapshot.observed_at),
            rieko_findings::ObservationReference::ChannelWindow {
                channel_id,
                snapshots,
            } => (
                channel_id,
                snapshots
                    .iter()
                    .map(|snapshot| snapshot.observed_at)
                    .max()
                    .ok_or_else(|| {
                        ModelError::InvalidInput(
                            "finding provenance has an empty observation window".into(),
                        )
                    })?,
            ),
        };
        if input.recommendation_target != parameters.source_channel
            || input.finding_channel != parameters.source_channel
            || provenance_channel != &parameters.source_channel
        {
            return Err(ModelError::InvalidInput(
                "source channel is not the recommendation's finding channel".into(),
            ));
        }
        if provenance_observed_at != input.source_snapshot.ts {
            return Err(ModelError::InvalidInput(
                "source snapshot is not the finding's observed state".into(),
            ));
        }
        if parameters.source_channel == parameters.destination_channel {
            return Err(ModelError::InvalidInput(
                "source and destination must differ".into(),
            ));
        }
        if parameters.amount_msat == 0 {
            return Err(ModelError::InvalidInput("amount must be > 0".into()));
        }
        if input.source_snapshot.channel_id != parameters.source_channel
            || input.destination_snapshot.channel_id != parameters.destination_channel
        {
            return Err(ModelError::InvalidInput(
                "snapshot identity does not match request parameters".into(),
            ));
        }
        if input.source_snapshot.node_id.as_deref() != Some(input.node_id.as_str())
            || input.destination_snapshot.node_id.as_deref() != Some(input.node_id.as_str())
        {
            return Err(ModelError::InvalidInput(
                "snapshot node identity does not match finding provenance".into(),
            ));
        }
        if input.source_snapshot.ts != input.destination_snapshot.ts {
            return Err(ModelError::InvalidInput(
                "source and destination snapshots must come from the same observation".into(),
            ));
        }

        validate_snapshot("source", &input.source_snapshot)?;
        validate_snapshot("destination", &input.destination_snapshot)?;
        let amount = parameters.amount_msat;
        if amount > input.source_snapshot.spendable_outbound_msat {
            return Err(ModelError::InvalidInput(format!(
                "amount {amount} msat exceeds source spendable outbound liquidity {} msat",
                input.source_snapshot.spendable_outbound_msat
            )));
        }
        if amount > input.destination_snapshot.spendable_inbound_msat {
            return Err(ModelError::InvalidInput(format!(
                "amount {amount} msat exceeds destination spendable inbound liquidity {} msat",
                input.destination_snapshot.spendable_inbound_msat
            )));
        }
        if amount > input.source_snapshot.local_balance_msat
            || amount > input.destination_snapshot.remote_balance_msat
        {
            return Err(ModelError::InvalidInput(
                "amount exceeds recorded channel-side balance".into(),
            ));
        }
        input
            .destination_snapshot
            .local_balance_msat
            .checked_add(amount)
            .filter(|balance| *balance <= input.destination_snapshot.capacity_msat)
            .ok_or_else(|| {
                ModelError::InvalidInput("amount would overflow destination capacity".into())
            })?;
        Ok(())
    }

    fn simulate(&self, input: &SimulationInput) -> Result<SimulationResult, ModelError> {
        self.validate(input)?;
        let amount = input.parameters.amount_msat;
        let source = &input.source_snapshot;
        let destination = &input.destination_snapshot;
        let source_local_after = source
            .local_balance_msat
            .checked_sub(amount)
            .ok_or_else(|| ModelError::CalculationFailed("source local underflow".into()))?;
        let source_remote_after = source
            .remote_balance_msat
            .checked_add(amount)
            .ok_or_else(|| ModelError::CalculationFailed("source remote overflow".into()))?;
        let destination_local_after = destination
            .local_balance_msat
            .checked_add(amount)
            .ok_or_else(|| ModelError::CalculationFailed("destination local overflow".into()))?;
        let destination_remote_after = destination
            .remote_balance_msat
            .checked_sub(amount)
            .ok_or_else(|| ModelError::CalculationFailed("destination remote underflow".into()))?;
        let source_profile = rieko_domain::LiquidityProfile::compute(
            source.capacity_msat,
            source_local_after,
            source_remote_after,
        );
        let input_hash = compute_input_hash(input)?;

        Ok(SimulationResult {
            model_id: self.model_id().into(),
            model_version: self.model_version().into(),
            input_hash,
            baseline: state(
                source.local_balance_msat,
                source.remote_balance_msat,
                source.capacity_msat,
            ),
            projected: state(
                source_local_after,
                source_remote_after,
                source.capacity_msat,
            ),
            deltas: vec![
                ProjectedDelta {
                    channel_id: source.channel_id.clone(),
                    local_before_msat: source.local_balance_msat,
                    local_after_msat: source_local_after,
                    remote_before_msat: source.remote_balance_msat,
                    remote_after_msat: source_remote_after,
                    delta_msat: amount,
                    clears_finding: source_profile.imbalance
                        == rieko_domain::LiquidityImbalance::Balanced,
                },
                ProjectedDelta {
                    channel_id: destination.channel_id.clone(),
                    local_before_msat: destination.local_balance_msat,
                    local_after_msat: destination_local_after,
                    remote_before_msat: destination.remote_balance_msat,
                    remote_after_msat: destination_remote_after,
                    delta_msat: amount,
                    clears_finding: false,
                },
            ],
            assumptions: vec![
                Assumption::new(
                    "fees_not_estimated",
                    "Routing fees are not estimated; actual cost may vary",
                ),
                Assumption::new(
                    "external_network_state_unmodelled",
                    "Only recorded local channel state is modelled",
                ),
            ],
            warnings: Vec::new(),
            confidence: SimulationConfidence::Medium,
        })
    }
}

fn validate_snapshot(label: &str, snapshot: &ChannelSnapshot) -> Result<(), ModelError> {
    if snapshot.status != ChannelStatus::Active {
        return Err(ModelError::InvalidInput(format!(
            "{label} channel {} is not active",
            snapshot.channel_id
        )));
    }
    if snapshot.capacity_msat == 0 {
        return Err(ModelError::InvalidInput(format!(
            "{label} channel {} has zero capacity",
            snapshot.channel_id
        )));
    }
    if snapshot.local_balance_msat > snapshot.capacity_msat
        || snapshot.remote_balance_msat > snapshot.capacity_msat
        || match snapshot
            .local_balance_msat
            .checked_add(snapshot.remote_balance_msat)
        {
            Some(total) => total > snapshot.capacity_msat,
            None => true,
        }
    {
        return Err(ModelError::InvalidInput(format!(
            "{label} channel {} has incoherent balances",
            snapshot.channel_id
        )));
    }
    if !snapshot.local_ratio.is_finite() || !(0.0..=1.0).contains(&snapshot.local_ratio) {
        return Err(ModelError::InvalidInput(format!(
            "{label} channel {} has an invalid local ratio",
            snapshot.channel_id
        )));
    }
    Ok(())
}

fn state(local: u64, remote: u64, capacity: u64) -> ProjectedState {
    ProjectedState {
        local_ratio: local as f64 / capacity as f64,
        local_balance_msat: local,
        remote_balance_msat: remote,
        capacity_msat: capacity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(id: &str, local: u64, remote: u64, ts: DateTime<Utc>) -> ChannelSnapshot {
        ChannelSnapshot {
            node_id: Some("node-1".into()),
            channel_id: id.into(),
            local_ratio: local as f64 / (local + remote) as f64,
            local_balance_msat: local,
            remote_balance_msat: remote,
            capacity_msat: local + remote,
            status: ChannelStatus::Active,
            ts,
            spendable_outbound_msat: local.saturating_sub(10_000),
            spendable_inbound_msat: remote.saturating_sub(10_000),
        }
    }

    fn input() -> SimulationInput {
        let ts = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        SimulationInput {
            recommendation_id: "rec1".into(),
            recommendation_target: "c1".into(),
            finding_id: "f1".into(),
            finding_channel: "c1".into(),
            node_id: "node-1".into(),
            provenance: rieko_findings::FindingProvenance {
                source: rieko_findings::ObservationSource::Fixture {
                    redacted_hash: "fixture-hash".into(),
                },
                producers: Vec::new(),
                observation: rieko_findings::ObservationReference::ChannelState {
                    channel_id: "c1".into(),
                    snapshot: rieko_findings::ChannelSnapshotReference {
                        observed_at: ts,
                        state_digest: "state-hash".into(),
                    },
                },
            },
            action_type: ActionType::RebalanceChannel,
            model_id: "liquidity-redistribution".into(),
            model_version: "2".into(),
            parameters: LiquidityRedistributionParameters {
                source_channel: "c1".into(),
                destination_channel: "c2".into(),
                amount_msat: 50_000,
            },
            source_snapshot: snapshot("c1", 200_000, 800_000, ts),
            destination_snapshot: snapshot("c2", 700_000, 300_000, ts),
        }
    }

    #[test]
    fn identical_inputs_produce_identical_complete_outputs() {
        let model = LiquidityRedistributionModel::new();
        let input = input();
        assert_eq!(
            model.simulate(&input).unwrap(),
            model.simulate(&input).unwrap()
        );
        assert_eq!(
            compute_input_hash(&input).unwrap(),
            compute_input_hash(&input).unwrap()
        );
    }

    #[test]
    fn model_version_changes_input_identity() {
        let input = input();
        let mut changed = input.clone();
        changed.model_version = "3".into();
        assert_ne!(
            compute_input_hash(&input).unwrap(),
            compute_input_hash(&changed).unwrap()
        );
    }

    #[test]
    fn valid_redistribution_preserves_recorded_balances() {
        let result = LiquidityRedistributionModel::new()
            .simulate(&input())
            .unwrap();
        assert_eq!(result.deltas[0].local_after_msat, 150_000);
        assert_eq!(result.deltas[0].remote_after_msat, 850_000);
        assert_eq!(result.deltas[1].local_after_msat, 750_000);
        assert_eq!(result.deltas[1].remote_after_msat, 250_000);
    }

    #[test]
    fn unsupported_action_and_mismatched_model_fail_closed() {
        let model = LiquidityRedistributionModel::new();
        let mut unsupported = input();
        unsupported.action_type = ActionType::UpdateFeePolicy;
        assert!(matches!(
            model.simulate(&unsupported),
            Err(ModelError::Unsupported { .. })
        ));

        let mut mismatched = input();
        mismatched.model_version = "1".into();
        assert!(matches!(
            model.simulate(&mismatched),
            Err(ModelError::InvalidInput(_))
        ));
    }

    #[test]
    fn mixed_observations_and_incoherent_state_fail() {
        let model = LiquidityRedistributionModel::new();
        let mut mixed = input();
        mixed.destination_snapshot.ts += Duration::seconds(1);
        assert!(model.validate(&mixed).is_err());

        let mut incoherent = input();
        incoherent.source_snapshot.remote_balance_msat = 900_000;
        assert!(model.validate(&incoherent).is_err());

        let mut unrelated = input();
        unrelated.recommendation_target = "other-channel".into();
        assert!(model.validate(&unrelated).is_err());
    }

    #[test]
    fn spendable_liquidity_is_enforced() {
        let model = LiquidityRedistributionModel::new();
        let mut request = input();
        request.source_snapshot.spendable_outbound_msat = 49_999;
        assert!(model.validate(&request).is_err());
        request.source_snapshot.spendable_outbound_msat = 190_000;
        request.destination_snapshot.spendable_inbound_msat = 49_999;
        assert!(model.validate(&request).is_err());
    }

    #[test]
    fn staleness_is_derived_without_changing_input() {
        let input = input();
        assert!(!input.is_stale_at(
            input.observed_at() + Duration::minutes(15),
            DEFAULT_FRESHNESS
        ));
        assert!(input.is_stale_at(
            input.observed_at() + Duration::minutes(15) + Duration::seconds(1),
            DEFAULT_FRESHNESS
        ));
        assert!(input.is_future_at(input.observed_at() - Duration::seconds(1)));
    }
}
