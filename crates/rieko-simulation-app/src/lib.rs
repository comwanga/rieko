//! Storage-backed application service for v2 simulations.
//!
//! The pure model remains in `rieko-simulation`; this crate owns authoritative
//! lookup, lifecycle persistence, reuse, and transport-neutral public views.

use chrono::{DateTime, Utc};
use rieko_domain::BitcoinNetwork;
use rieko_findings::{Finding, FindingLifecycle, ObservationReference, Recommendation};
use rieko_simulation::model::{
    compute_input_hash, FindingDirection, LiquidityRedistributionModel,
    LiquidityRedistributionParameters, ModelError, SimulationConfidence, SimulationInput,
    SimulationModel, SimulationResult, SimulationStatus, DEFAULT_FRESHNESS,
};
use rieko_storage::{SimulationEvent, SimulationRecord, Storage, StorageError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MODEL_ID: &str = "liquidity-redistribution";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSimulationCommand {
    pub recommendation_id: String,
    pub model_id: String,
    pub source_channel: String,
    pub destination_channel: String,
    pub amount_sats: u64,
    #[serde(default)]
    pub allow_stale: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationView {
    pub id: String,
    pub recommendation_id: String,
    pub finding_id: String,
    pub action_type: String,
    pub status: SimulationStatus,
    pub model_id: String,
    pub model_version: String,
    pub input_hash: String,
    pub parameters: LiquidityRedistributionParameters,
    pub source_observed_at: DateTime<Utc>,
    pub stale: bool,
    pub confidence: SimulationConfidence,
    pub result: Option<SimulationResult>,
    pub explanation: String,
    pub error_code: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub no_action_executed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateSimulationOutcome {
    pub simulation: SimulationView,
    pub reused: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompareSimulationsCommand {
    pub left_simulation_id: String,
    pub right_simulation_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationComparison {
    pub recommendation_id: String,
    pub left: SimulationView,
    pub right: SimulationView,
    pub projected_local_ratio_delta: f64,
    pub projected_local_balance_delta_msat: i64,
    pub no_action_executed: bool,
    pub freshness_delta_seconds: i64,
    pub confidence_left: SimulationConfidence,
    pub confidence_right: SimulationConfidence,
    pub warnings_left: usize,
    pub warnings_right: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationReport {
    pub rieko_version: String,
    pub model_id: String,
    pub model_version: String,
    pub simulation_id: String,
    pub input_hash: String,
    pub recommendation_id: String,
    pub finding_id: String,
    pub snapshot_observed_at: DateTime<Utc>,
    pub parameters: LiquidityRedistributionParameters,
    pub baseline: Option<rieko_simulation::model::ProjectedState>,
    pub projected: Option<rieko_simulation::model::ProjectedState>,
    pub deltas: Vec<rieko_simulation::model::ProjectedDelta>,
    pub assumptions: Vec<rieko_simulation::model::Assumption>,
    pub warnings: Vec<rieko_simulation::model::SimulationWarning>,
    pub confidence: SimulationConfidence,
    pub stale: bool,
    pub explanation: String,
    pub generated_at: DateTime<Utc>,
    pub no_action_executed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationAppErrorKind {
    InvalidRequest,
    UnknownModel,
    RecommendationNotFound,
    FindingNotFound,
    SimulationNotFound,
    FindingInactive,
    MissingContext,
    SnapshotNotFound,
    StaleInput,
    FutureDatedInput,
    UnsupportedRecommendation,
    InvalidInput,
    IncompatibleSimulations,
    Storage,
    ModelFailure,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct SimulationAppError {
    pub kind: SimulationAppErrorKind,
    pub message: String,
    pub simulation: Option<Box<SimulationView>>,
}

impl SimulationAppError {
    fn new(kind: SimulationAppErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            simulation: None,
        }
    }

    fn with_simulation(
        kind: SimulationAppErrorKind,
        message: impl Into<String>,
        simulation: SimulationView,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            simulation: Some(Box::new(simulation)),
        }
    }

    fn storage(error: StorageError) -> Self {
        Self::new(SimulationAppErrorKind::Storage, error.to_string())
    }
}

pub fn create_simulation(
    storage: &mut dyn Storage,
    command: CreateSimulationCommand,
) -> Result<CreateSimulationOutcome, SimulationAppError> {
    validate_command(&command)?;
    let model = LiquidityRedistributionModel::new();
    if command.model_id != model.model_id() {
        return Err(SimulationAppError::new(
            SimulationAppErrorKind::UnknownModel,
            format!("unknown simulation model: {}", command.model_id),
        ));
    }
    let amount_msat = command.amount_sats.checked_mul(1_000).ok_or_else(|| {
        SimulationAppError::new(
            SimulationAppErrorKind::InvalidRequest,
            "amount_sats is too large",
        )
    })?;

    storage
        .begin_transaction()
        .map_err(SimulationAppError::storage)?;
    let result = create_in_transaction(storage, command, amount_msat, &model);
    match result {
        Ok((outcome, wrote)) => {
            let transaction_result = if wrote {
                storage.commit_transaction()
            } else {
                storage.rollback_transaction()
            };
            if let Err(error) = transaction_result {
                let _ = storage.rollback_transaction();
                return Err(SimulationAppError::storage(error));
            }
            Ok(outcome)
        }
        Err(error) => {
            if error.simulation.is_some() {
                if let Err(commit_error) = storage.commit_transaction() {
                    let _ = storage.rollback_transaction();
                    return Err(SimulationAppError::storage(commit_error));
                }
            } else {
                storage
                    .rollback_transaction()
                    .map_err(SimulationAppError::storage)?;
            }
            Err(error)
        }
    }
}

fn create_in_transaction(
    storage: &mut dyn Storage,
    command: CreateSimulationCommand,
    amount_msat: u64,
    model: &LiquidityRedistributionModel,
) -> Result<(CreateSimulationOutcome, bool), SimulationAppError> {
    let recommendation = storage
        .recommendation_for_action(&command.recommendation_id)
        .map_err(SimulationAppError::storage)?
        .ok_or_else(|| {
            SimulationAppError::new(
                SimulationAppErrorKind::RecommendationNotFound,
                format!("no recommendation with id {}", command.recommendation_id),
            )
        })?;
    let supported = model.supports(&recommendation);
    let finding = storage
        .finding_by_id(&recommendation.finding_id)
        .map_err(SimulationAppError::storage)?
        .ok_or_else(|| {
            context_or_unsupported(
                supported,
                SimulationAppError::new(
                    SimulationAppErrorKind::FindingNotFound,
                    format!("no finding with id {}", recommendation.finding_id),
                ),
            )
        })?;
    if finding.lifecycle != FindingLifecycle::Active {
        return Err(context_or_unsupported(
            supported,
            SimulationAppError::new(
                SimulationAppErrorKind::FindingInactive,
                format!("finding {} is not active", finding.id),
            ),
        ));
    }
    let finding_direction = if supported {
        Some(parse_finding_direction(&finding)?)
    } else {
        None
    };
    let node_id = required(finding.node, "finding has no node identity")
        .map_err(|error| context_or_unsupported(supported, error))?;
    let provenance = finding.provenance.ok_or_else(|| {
        context_or_unsupported(
            supported,
            SimulationAppError::new(
                SimulationAppErrorKind::MissingContext,
                "finding has no observation provenance",
            ),
        )
    })?;
    let (network, observed_at) = referenced_observation(&provenance)
        .map_err(|error| context_or_unsupported(supported, error))?;
    let finding_channel = required(finding.channel, "finding has no channel identity")
        .map_err(|error| context_or_unsupported(supported, error))?;
    let recommendation_target = required(
        recommendation.action.target.clone(),
        "recommendation has no channel target",
    )
    .map_err(|error| context_or_unsupported(supported, error))?;
    let source_snapshot = snapshot_at(
        storage,
        network,
        &node_id,
        &command.source_channel,
        observed_at,
        "source",
    )
    .map_err(|error| context_or_unsupported(supported, error))?;
    let destination_snapshot = snapshot_at(
        storage,
        network,
        &node_id,
        &command.destination_channel,
        observed_at,
        "destination",
    )
    .map_err(|error| context_or_unsupported(supported, error))?;
    let input = SimulationInput {
        recommendation_id: recommendation.action.id.clone(),
        recommendation_target,
        finding_id: recommendation.finding_id.clone(),
        finding_channel,
        finding_direction,
        node_id,
        network: Some(network),
        provenance,
        action_type: recommendation.action.action_type,
        model_id: model.model_id().into(),
        model_version: model.model_version().into(),
        parameters: LiquidityRedistributionParameters {
            source_channel: command.source_channel,
            destination_channel: command.destination_channel,
            amount_msat,
        },
        source_snapshot,
        destination_snapshot,
    };
    let input_hash = compute_input_hash(&input).map_err(model_error)?;
    if let Some(existing) = storage
        .simulation_v2_by_input_hash(&input_hash)
        .map_err(SimulationAppError::storage)?
    {
        if !existing.projection.is_null() {
            let view = simulation_view(&existing, Utc::now())?;
            if view.stale && !command.allow_stale {
                return Err(SimulationAppError::with_simulation(
                    SimulationAppErrorKind::StaleInput,
                    "identical simulation result is stale; inspect it before allowing stale input",
                    view,
                ));
            }
            return Ok((
                CreateSimulationOutcome {
                    simulation: view,
                    reused: true,
                },
                false,
            ));
        }
        if !(command.allow_stale && existing.status == "stale") {
            let view = simulation_view(&existing, Utc::now())?;
            return Err(SimulationAppError::with_simulation(
                error_kind_for_view(&view),
                format!(
                    "identical simulation request {} already ended with status {}",
                    existing.id,
                    view.status.as_str()
                ),
                view,
            ));
        }
    }

    evaluate_and_persist(
        storage,
        recommendation,
        input,
        input_hash,
        command.allow_stale,
        model,
    )
}

fn evaluate_and_persist(
    storage: &mut dyn Storage,
    recommendation: Recommendation,
    input: SimulationInput,
    input_hash: String,
    allow_stale: bool,
    model: &LiquidityRedistributionModel,
) -> Result<(CreateSimulationOutcome, bool), SimulationAppError> {
    let requested_at = Utc::now();
    let stale = input.is_stale_at(requested_at, DEFAULT_FRESHNESS);
    let stale_refused = stale && !allow_stale;
    let outcome = if !model.supports(&recommendation) {
        Err(ModelError::Unsupported {
            model_id: model.model_id().into(),
        })
    } else if input.is_future_at(requested_at) {
        Err(ModelError::InvalidInput(
            "source snapshots are dated after the simulation request".into(),
        ))
    } else if stale_refused {
        Err(ModelError::InvalidInput(
            "source snapshots are stale; inspect them before allowing stale input".into(),
        ))
    } else {
        model.simulate(&input)
    };
    let id = uuid::Uuid::new_v4().to_string();
    let (status, projection, error_code, message, kind) = match outcome {
        Ok(result) if stale => (SimulationStatus::Stale, Some(result), None, None, None),
        Ok(result) => (SimulationStatus::Completed, Some(result), None, None, None),
        Err(ModelError::Unsupported { .. }) => (
            SimulationStatus::Unsupported,
            None,
            Some("unsupported_recommendation".into()),
            Some("recommendation type is unsupported by this model".into()),
            Some(SimulationAppErrorKind::UnsupportedRecommendation),
        ),
        Err(ModelError::InvalidInput(message)) => (
            if stale_refused {
                SimulationStatus::Stale
            } else {
                SimulationStatus::InvalidInput
            },
            None,
            Some(
                if stale_refused {
                    "stale_input"
                } else if input.is_future_at(requested_at) {
                    "future_dated_input"
                } else {
                    "invalid_input"
                }
                .into(),
            ),
            Some(message),
            Some(if stale_refused {
                SimulationAppErrorKind::StaleInput
            } else if input.is_future_at(requested_at) {
                SimulationAppErrorKind::FutureDatedInput
            } else {
                SimulationAppErrorKind::InvalidInput
            }),
        ),
        Err(error) => (
            SimulationStatus::Failed,
            None,
            Some("model_failure".into()),
            Some(error.to_string()),
            Some(SimulationAppErrorKind::ModelFailure),
        ),
    };
    let completed_at = Utc::now();
    let record = simulation_record(
        &id,
        &recommendation,
        &input,
        &input_hash,
        status,
        projection.as_ref(),
        requested_at,
        completed_at,
        error_code.clone(),
    )?;
    persist_outcome(storage, &record, error_code)?;
    let view = simulation_view(&record, completed_at)?;
    if let (Some(kind), Some(message)) = (kind, message) {
        Err(SimulationAppError::with_simulation(kind, message, view))
    } else {
        Ok((
            CreateSimulationOutcome {
                simulation: view,
                reused: false,
            },
            true,
        ))
    }
}

pub fn get_simulation(
    storage: &mut dyn Storage,
    simulation_id: &str,
) -> Result<Option<SimulationView>, SimulationAppError> {
    storage
        .replayable_simulation_v2_by_id(simulation_id)
        .map_err(SimulationAppError::storage)?
        .map(|record| simulation_view(&record, Utc::now()))
        .transpose()
}

pub fn list_simulations(
    storage: &mut dyn Storage,
    limit: u32,
) -> Result<Vec<SimulationView>, SimulationAppError> {
    storage
        .recent_replayable_simulations_v2(limit)
        .map_err(SimulationAppError::storage)?
        .iter()
        .map(|record| simulation_view(record, Utc::now()))
        .collect()
}

pub fn compare_simulations(
    storage: &mut dyn Storage,
    command: CompareSimulationsCommand,
) -> Result<SimulationComparison, SimulationAppError> {
    if command.left_simulation_id.trim().is_empty() || command.right_simulation_id.trim().is_empty()
    {
        return Err(SimulationAppError::new(
            SimulationAppErrorKind::InvalidRequest,
            "simulation IDs cannot be empty",
        ));
    }
    let left = get_simulation(storage, &command.left_simulation_id)?.ok_or_else(|| {
        SimulationAppError::new(
            SimulationAppErrorKind::SimulationNotFound,
            format!("no simulation with id {}", command.left_simulation_id),
        )
    })?;
    let right = get_simulation(storage, &command.right_simulation_id)?.ok_or_else(|| {
        SimulationAppError::new(
            SimulationAppErrorKind::SimulationNotFound,
            format!("no simulation with id {}", command.right_simulation_id),
        )
    })?;
    if left.recommendation_id != right.recommendation_id
        || left.model_id != right.model_id
        || left.model_version != right.model_version
        || left.result.is_none()
        || right.result.is_none()
    {
        return Err(SimulationAppError::new(
            SimulationAppErrorKind::IncompatibleSimulations,
            "simulations must be completed projections for the same recommendation and model",
        ));
    }
    let left_result = left.result.as_ref().expect("checked above");
    let right_result = right.result.as_ref().expect("checked above");
    let balance_delta = i128::from(right_result.projected.local_balance_msat)
        - i128::from(left_result.projected.local_balance_msat);
    let projected_local_balance_delta_msat = i64::try_from(balance_delta).map_err(|_| {
        SimulationAppError::new(
            SimulationAppErrorKind::IncompatibleSimulations,
            "projected balance difference exceeds the supported comparison range",
        )
    })?;
    let freshness_delta = (right.source_observed_at - left.source_observed_at).num_seconds();
    let confidence_left = left_result.confidence;
    let confidence_right = right_result.confidence;
    let warnings_left = left_result.warnings.len();
    let warnings_right = right_result.warnings.len();
    Ok(SimulationComparison {
        recommendation_id: left.recommendation_id.clone(),
        projected_local_ratio_delta: right_result.projected.local_ratio
            - left_result.projected.local_ratio,
        projected_local_balance_delta_msat,
        left,
        right,
        no_action_executed: true,
        freshness_delta_seconds: freshness_delta,
        confidence_left,
        confidence_right,
        warnings_left,
        warnings_right,
    })
}

pub fn simulation_view(
    record: &SimulationRecord,
    now: DateTime<Utc>,
) -> Result<SimulationView, SimulationAppError> {
    let input: SimulationInput =
        serde_json::from_value(record.canonical_input.clone()).map_err(|error| {
            SimulationAppError::new(
                SimulationAppErrorKind::Storage,
                format!("invalid canonical simulation input: {error}"),
            )
        })?;
    let result: Option<SimulationResult> = if record.projection.is_null() {
        None
    } else {
        Some(
            serde_json::from_value(record.projection.clone()).map_err(|error| {
                SimulationAppError::new(
                    SimulationAppErrorKind::Storage,
                    format!("invalid deterministic simulation result: {error}"),
                )
            })?,
        )
    };
    let persisted_status = parse_status(&record.status)?;
    let stale = input.is_stale_at(now, DEFAULT_FRESHNESS);
    let status = if persisted_status == SimulationStatus::Completed && stale {
        SimulationStatus::Stale
    } else {
        persisted_status
    };
    let requested_at = parse_time("requested_at", &record.requested_at)?;
    let completed_at = record
        .completed_at
        .as_deref()
        .map(|timestamp| parse_time("completed_at", timestamp))
        .transpose()?;
    let confidence = result
        .as_ref()
        .map(|result| result.confidence)
        .unwrap_or(SimulationConfidence::Unknown);
    Ok(SimulationView {
        id: record.id.clone(),
        recommendation_id: record.action_id.clone(),
        finding_id: record.finding_id.clone(),
        action_type: record.action_type.clone(),
        status,
        model_id: record.model_id.clone(),
        model_version: record.model_version.clone(),
        input_hash: record.input_hash.clone(),
        parameters: input.parameters.clone(),
        source_observed_at: input.observed_at(),
        stale,
        confidence,
        result,
        explanation: record.explanation.clone(),
        error_code: record.error_code.clone(),
        requested_at,
        completed_at,
        no_action_executed: true,
    })
}

fn validate_command(command: &CreateSimulationCommand) -> Result<(), SimulationAppError> {
    for (name, value) in [
        ("recommendation_id", command.recommendation_id.as_str()),
        ("model_id", command.model_id.as_str()),
        ("source_channel", command.source_channel.as_str()),
        ("destination_channel", command.destination_channel.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(SimulationAppError::new(
                SimulationAppErrorKind::InvalidRequest,
                format!("{name} cannot be empty"),
            ));
        }
    }
    if command.amount_sats == 0 {
        return Err(SimulationAppError::new(
            SimulationAppErrorKind::InvalidRequest,
            "amount_sats must be greater than zero",
        ));
    }
    Ok(())
}

fn required(value: Option<String>, message: &str) -> Result<String, SimulationAppError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| SimulationAppError::new(SimulationAppErrorKind::MissingContext, message))
}

fn context_or_unsupported(
    supported: bool,
    context_error: SimulationAppError,
) -> SimulationAppError {
    if supported || context_error.kind == SimulationAppErrorKind::Storage {
        context_error
    } else {
        SimulationAppError::new(
            SimulationAppErrorKind::UnsupportedRecommendation,
            "recommendation type is unsupported by this model",
        )
    }
}

fn snapshot_at(
    storage: &mut dyn Storage,
    network: BitcoinNetwork,
    node_id: &str,
    channel_id: &str,
    observed_at: DateTime<Utc>,
    role: &str,
) -> Result<rieko_domain::ChannelSnapshot, SimulationAppError> {
    storage
        .channel_snapshot_at(network, node_id, channel_id, observed_at)
        .map_err(SimulationAppError::storage)?
        .ok_or_else(|| {
            SimulationAppError::new(
                SimulationAppErrorKind::SnapshotNotFound,
                format!("no {network} snapshot for {role} channel {channel_id} at {observed_at}"),
            )
        })
}

fn referenced_observation(
    provenance: &rieko_findings::FindingProvenance,
) -> Result<(BitcoinNetwork, DateTime<Utc>), SimulationAppError> {
    let network = provenance.network.ok_or_else(|| {
        SimulationAppError::new(
            SimulationAppErrorKind::MissingContext,
            "finding provenance has no network identity",
        )
    })?;
    let reference = match &provenance.observation {
        ObservationReference::ChannelState { snapshot, .. } => snapshot,
        ObservationReference::ChannelWindow { snapshots, .. } => snapshots
            .iter()
            .max_by_key(|snapshot| snapshot.observed_at)
            .ok_or_else(|| {
                SimulationAppError::new(
                    SimulationAppErrorKind::MissingContext,
                    "finding provenance has an empty observation window",
                )
            })?,
    };
    if reference.network != Some(network) {
        return Err(SimulationAppError::new(
            SimulationAppErrorKind::MissingContext,
            "snapshot reference network does not match finding provenance",
        ));
    }
    Ok((network, reference.observed_at))
}

fn parse_finding_direction(finding: &Finding) -> Result<FindingDirection, SimulationAppError> {
    if finding.detector != "channel_liquidity" {
        return Err(SimulationAppError::new(
            SimulationAppErrorKind::UnsupportedRecommendation,
            format!(
                "finding detector {} is unsupported by this model",
                finding.detector
            ),
        ));
    }
    let mut directions = finding
        .evidence
        .iter()
        .filter(|evidence| evidence.key == "direction");
    let value = directions
        .next()
        .and_then(|evidence| evidence.value.as_str());
    if value.is_none() || directions.next().is_some() {
        return Err(SimulationAppError::new(
            SimulationAppErrorKind::InvalidInput,
            "finding must contain one string direction evidence value",
        ));
    }
    match value {
        Some("outbound") => Ok(FindingDirection::Outbound),
        Some("inbound") => Ok(FindingDirection::Inbound),
        _ => Err(SimulationAppError::new(
            SimulationAppErrorKind::InvalidInput,
            "finding direction must be outbound or inbound",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn simulation_record(
    id: &str,
    recommendation: &Recommendation,
    input: &SimulationInput,
    input_hash: &str,
    status: SimulationStatus,
    result: Option<&SimulationResult>,
    requested_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    error_code: Option<String>,
) -> Result<SimulationRecord, SimulationAppError> {
    Ok(SimulationRecord {
        id: id.into(),
        action_id: recommendation.action.id.clone(),
        finding_id: recommendation.finding_id.clone(),
        action_type: recommendation.action.action_type.as_str().into(),
        status: status.as_str().into(),
        model_id: input.model_id.clone(),
        model_version: input.model_version.clone(),
        input_hash: input_hash.into(),
        confidence: result
            .map(|result| result.confidence.as_str())
            .unwrap_or("unknown")
            .into(),
        assumptions: result
            .map(|result| serde_json::to_value(&result.assumptions))
            .transpose()
            .map_err(json_error)?
            .unwrap_or_else(|| serde_json::json!([])),
        warnings: result
            .map(|result| serde_json::to_value(&result.warnings))
            .transpose()
            .map_err(json_error)?
            .unwrap_or_else(|| serde_json::json!([])),
        explanation: generate_summary(input, result),
        canonical_input: serde_json::to_value(input).map_err(json_error)?,
        projection: result
            .map(serde_json::to_value)
            .transpose()
            .map_err(json_error)?
            .unwrap_or(serde_json::Value::Null),
        source_observed_at: Some(input.observed_at().to_rfc3339()),
        requested_at: requested_at.to_rfc3339(),
        completed_at: Some(completed_at.to_rfc3339()),
        error_code,
        created_at: requested_at.to_rfc3339(),
    })
}

fn persist_outcome(
    storage: &mut dyn Storage,
    record: &SimulationRecord,
    error_code: Option<String>,
) -> Result<(), SimulationAppError> {
    storage
        .save_simulation_v2(record)
        .map_err(SimulationAppError::storage)?;
    for (status, error_code, timestamp) in [
        (
            SimulationStatus::Requested,
            None,
            record.requested_at.clone(),
        ),
        (
            parse_status(&record.status)?,
            error_code,
            record
                .completed_at
                .clone()
                .unwrap_or_else(|| record.requested_at.clone()),
        ),
    ] {
        storage
            .append_simulation_event(&SimulationEvent {
                id: uuid::Uuid::new_v4().to_string(),
                simulation_id: record.id.clone(),
                status: status.as_str().into(),
                error_code,
                timestamp,
            })
            .map_err(SimulationAppError::storage)?;
    }
    Ok(())
}

fn parse_status(status: &str) -> Result<SimulationStatus, SimulationAppError> {
    match status {
        "requested" => Ok(SimulationStatus::Requested),
        "completed" => Ok(SimulationStatus::Completed),
        "unsupported" => Ok(SimulationStatus::Unsupported),
        "invalid_input" => Ok(SimulationStatus::InvalidInput),
        "stale" => Ok(SimulationStatus::Stale),
        "failed" => Ok(SimulationStatus::Failed),
        _ => Err(SimulationAppError::new(
            SimulationAppErrorKind::Storage,
            format!("invalid persisted simulation status {status:?}"),
        )),
    }
}

fn error_kind_for_view(view: &SimulationView) -> SimulationAppErrorKind {
    if view.error_code.as_deref() == Some("future_dated_input") {
        return SimulationAppErrorKind::FutureDatedInput;
    }
    match view.status {
        SimulationStatus::Unsupported => SimulationAppErrorKind::UnsupportedRecommendation,
        SimulationStatus::InvalidInput => SimulationAppErrorKind::InvalidInput,
        SimulationStatus::Stale => SimulationAppErrorKind::StaleInput,
        SimulationStatus::Failed => SimulationAppErrorKind::ModelFailure,
        _ => SimulationAppErrorKind::InvalidInput,
    }
}

fn parse_time(label: &str, value: &str) -> Result<DateTime<Utc>, SimulationAppError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| {
            SimulationAppError::new(
                SimulationAppErrorKind::Storage,
                format!("invalid simulation {label} {value:?}: {error}"),
            )
        })
}

fn model_error(error: ModelError) -> SimulationAppError {
    SimulationAppError::new(SimulationAppErrorKind::ModelFailure, error.to_string())
}

fn json_error(error: serde_json::Error) -> SimulationAppError {
    SimulationAppError::new(SimulationAppErrorKind::Storage, error.to_string())
}

fn generate_summary(input: &SimulationInput, result: Option<&SimulationResult>) -> String {
    let Some(result) = result else {
        return String::new();
    };
    let amount = input.parameters.amount_msat;
    let from = &input.parameters.source_channel;
    let to = &input.parameters.destination_channel;
    let baseline_local = result.baseline.local_balance_msat;
    let projected_local = result.projected.local_balance_msat;
    let delta = projected_local as i128 - baseline_local as i128;
    let mut summary = format!(
        "Simulated a rebalance of {} sats from channel {} to {}. ",
        amount / 1000,
        &from[..from.len().min(8)],
        &to[..to.len().min(8)],
    );
    summary.push_str(&format!(
        "Baseline local balance: {} msat. Projected local balance: {} msat. ",
        baseline_local, projected_local,
    ));
    if delta > 0 {
        summary.push_str(&format!("Net increase: +{} msat. ", delta));
    } else if delta < 0 {
        summary.push_str(&format!("Net decrease: {} msat. ", delta));
    } else {
        summary.push_str("No net change. ");
    }
    let has_assumptions = !result.assumptions.is_empty();
    if has_assumptions {
        summary.push_str("Assumptions: ");
        for a in &result.assumptions {
            summary.push_str(&format!("[{}] {}; ", a.code, a.description));
        }
    }
    let has_warnings = !result.warnings.is_empty();
    if has_warnings {
        summary.push_str("Warnings: ");
        for w in &result.warnings {
            summary.push_str(&format!("[{}] {}; ", w.code, w.description));
        }
    }
    summary.push_str(&format!("Confidence: {}. ", result.confidence.as_str()));
    summary.push_str("This is a deterministic projection. Rieko did not execute any action.");
    summary
}

pub fn simulation_report(
    view: &SimulationView,
    version: &str,
    now: DateTime<Utc>,
) -> SimulationReport {
    SimulationReport {
        rieko_version: version.into(),
        model_id: view.model_id.clone(),
        model_version: view.model_version.clone(),
        simulation_id: view.id.clone(),
        input_hash: view.input_hash.clone(),
        recommendation_id: view.recommendation_id.clone(),
        finding_id: view.finding_id.clone(),
        snapshot_observed_at: view.source_observed_at,
        parameters: view.parameters.clone(),
        baseline: view.result.as_ref().map(|r| r.baseline.clone()),
        projected: view.result.as_ref().map(|r| r.projected.clone()),
        deltas: view
            .result
            .as_ref()
            .map(|r| r.deltas.clone())
            .unwrap_or_default(),
        assumptions: view
            .result
            .as_ref()
            .map(|r| r.assumptions.clone())
            .unwrap_or_default(),
        warnings: view
            .result
            .as_ref()
            .map(|r| r.warnings.clone())
            .unwrap_or_default(),
        confidence: view.confidence,
        stale: view.stale,
        explanation: view.explanation.clone(),
        generated_at: now,
        no_action_executed: view.no_action_executed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rieko_detectors::{Detector, DetectorContext, LiquidityDetector};
    use rieko_domain::{
        BitcoinNetwork, Channel, ChannelStatus, FeePolicy, LiquidityProfile, NodeId,
    };
    use rieko_findings::{channel_snapshot_state_digest, ObservationSource};
    use rieko_graph::{GraphStore, InMemoryGraph};
    use rieko_recommendations::RecommendationEngine;
    use rieko_storage::MemoryStorage;

    fn channel(id: &str, local: u64, remote: u64, observed_at: DateTime<Utc>) -> Channel {
        let mut liquidity = LiquidityProfile::compute(local + remote, local, remote);
        liquidity.spendable_outbound_msat = local.saturating_sub(10_000);
        liquidity.spendable_inbound_msat = remote.saturating_sub(10_000);
        Channel {
            id: id.into(),
            node: NodeId::new("local-node"),
            peer: NodeId::new(format!("peer-{id}")),
            capacity_msat: local + remote,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity,
            last_seen: observed_at,
            opening_height: Some(1),
            channel_point: format!("tx-{id}:0"),
            local_reserve_msat: Some(10_000),
            remote_reserve_msat: Some(10_000),
            is_private: false,
            is_initiator: true,
            total_sent_msat: None,
            total_received_msat: None,
        }
    }

    #[test]
    fn detector_recommendation_and_simulation_preserve_correct_outbound_direction() {
        let observed_at = Utc::now();
        let finding_channel = channel("c1", 50_000, 950_000, observed_at);
        let source_channel = channel("c2", 500_000, 500_000, observed_at);
        let mut graph = InMemoryGraph::new();
        graph
            .upsert_channels(vec![finding_channel.clone(), source_channel.clone()])
            .unwrap();
        let source = ObservationSource::Fixture {
            redacted_hash: "fixture-hash".into(),
            configured_node: "node-1".into(),
        };
        let detector = LiquidityDetector::new("local-node");
        let cycle = detector
            .evaluate(
                &graph,
                &DetectorContext {
                    network: BitcoinNetwork::Regtest,
                    history: None,
                    source: Some(&source),
                    normalizer: None,
                    node: Some("local-node"),
                },
            )
            .unwrap();
        let finding = cycle.findings.into_iter().next().unwrap();
        let recommendation = RecommendationEngine
            .recommend(&finding)
            .unwrap()
            .into_iter()
            .find(|recommendation| {
                recommendation.action.action_type == rieko_findings::ActionType::RebalanceChannel
            })
            .unwrap();

        let mut storage = MemoryStorage::new();
        storage.save_finding(&finding).unwrap();
        storage.save_recommendation(&recommendation).unwrap();
        for channel in [&finding_channel, &source_channel] {
            let mut snapshot = rieko_domain::ChannelSnapshot::from_channel(
                channel,
                observed_at,
                BitcoinNetwork::Regtest,
            );
            snapshot.state_digest = Some(channel_snapshot_state_digest(&snapshot));
            storage.save_channel_snapshot(&snapshot).unwrap();
        }
        for channel in [
            channel(
                "c1",
                10_000,
                990_000,
                observed_at + chrono::Duration::seconds(1),
            ),
            channel(
                "c2",
                900_000,
                100_000,
                observed_at + chrono::Duration::seconds(1),
            ),
        ] {
            let mut snapshot = rieko_domain::ChannelSnapshot::from_channel(
                &channel,
                channel.last_seen,
                BitcoinNetwork::Regtest,
            );
            snapshot.state_digest = Some(channel_snapshot_state_digest(&snapshot));
            storage.save_channel_snapshot(&snapshot).unwrap();
        }

        let outcome = create_simulation(
            &mut storage,
            CreateSimulationCommand {
                recommendation_id: recommendation.action.id,
                model_id: MODEL_ID.into(),
                source_channel: "c2".into(),
                destination_channel: "c1".into(),
                amount_sats: 50,
                allow_stale: false,
            },
        )
        .unwrap();
        let result = outcome.simulation.result.unwrap();
        assert_eq!(result.baseline.local_balance_msat, 50_000);
        assert_eq!(result.projected.local_balance_msat, 100_000);
        assert!(result.deltas[1].clears_finding);
        assert!(storage.latest_findings(10).unwrap()[0].lifecycle == FindingLifecycle::Active);
        assert_eq!(
            storage.latest_recommendations(10).unwrap()[0].action.stage,
            rieko_findings::ActionStage::Recommended
        );
    }
}
