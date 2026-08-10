//! Storage-backed application service for v2 simulations.
//!
//! The pure model remains in `rieko-simulation`; this crate owns authoritative
//! lookup, lifecycle persistence, reuse, and transport-neutral public views.

use chrono::{DateTime, Utc};
use rieko_findings::{FindingLifecycle, Recommendation};
use rieko_simulation::model::{
    compute_input_hash, LiquidityRedistributionModel, LiquidityRedistributionParameters,
    ModelError, SimulationConfidence, SimulationInput, SimulationModel, SimulationResult,
    SimulationStatus, DEFAULT_FRESHNESS,
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
    let finding_channel = required(finding.channel, "finding has no channel identity")
        .map_err(|error| context_or_unsupported(supported, error))?;
    let recommendation_target = required(
        recommendation.action.target.clone(),
        "recommendation has no channel target",
    )
    .map_err(|error| context_or_unsupported(supported, error))?;
    let source_snapshot = latest_snapshot(storage, &node_id, &command.source_channel, "source")
        .map_err(|error| context_or_unsupported(supported, error))?;
    let destination_snapshot = latest_snapshot(
        storage,
        &node_id,
        &command.destination_channel,
        "destination",
    )
    .map_err(|error| context_or_unsupported(supported, error))?;
    let input = SimulationInput {
        recommendation_id: recommendation.action.id.clone(),
        recommendation_target,
        finding_id: recommendation.finding_id.clone(),
        finding_channel,
        node_id,
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
                error_kind_for_status(view.status),
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
        .simulation_v2_by_id(simulation_id)
        .map_err(SimulationAppError::storage)?
        .map(|record| simulation_view(&record, Utc::now()))
        .transpose()
}

pub fn list_simulations(
    storage: &mut dyn Storage,
    limit: u32,
) -> Result<Vec<SimulationView>, SimulationAppError> {
    storage
        .recent_simulations_v2(limit)
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
    Ok(SimulationComparison {
        recommendation_id: left.recommendation_id.clone(),
        projected_local_ratio_delta: right_result.projected.local_ratio
            - left_result.projected.local_ratio,
        projected_local_balance_delta_msat,
        left,
        right,
        no_action_executed: true,
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

fn latest_snapshot(
    storage: &mut dyn Storage,
    node_id: &str,
    channel_id: &str,
    role: &str,
) -> Result<rieko_domain::ChannelSnapshot, SimulationAppError> {
    storage
        .recent_channel_snapshots_for_node(node_id, channel_id, 1)
        .map_err(SimulationAppError::storage)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            SimulationAppError::new(
                SimulationAppErrorKind::SnapshotNotFound,
                format!("no snapshot for {role} channel {channel_id}"),
            )
        })
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
        explanation: String::new(),
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

fn error_kind_for_status(status: SimulationStatus) -> SimulationAppErrorKind {
    match status {
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
