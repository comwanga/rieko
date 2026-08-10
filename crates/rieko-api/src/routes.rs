use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::app::{block_storage, VERSION};
use crate::RiekoApi;

#[cfg(feature = "simulate")]
use crate::app::{MAX_BODY_BYTES, REQUEST_TIMEOUT};
#[cfg(feature = "simulate")]
use axum::extract::rejection::JsonRejection;
#[cfg(feature = "simulate")]
use axum::extract::Request;
#[cfg(feature = "simulate")]
use rieko_simulation_app::{
    CompareSimulationsCommand, CreateSimulationOutcome, SimulationAppError, SimulationAppErrorKind,
    SimulationComparison, SimulationView,
};

#[derive(Serialize)]
pub struct Status {
    pub engine: &'static str,
    pub version: &'static str,
    pub schema_version: i64,
    pub read_only: bool,
    pub integrity: String,
    pub overall: String,
    pub source: Option<String>,
    pub source_data_at: Option<String>,
    pub last_ingestion: Option<OperationTimes>,
    pub last_cycle: Option<OperationTimes>,
    pub llm: String,
    pub alert_sink: String,
    pub cleanup: String,
    pub last_cleanup: Option<OperationTimes>,
    pub counts: StatusCounts,
}

#[derive(Serialize)]
pub struct OperationTimes {
    pub attempt: Option<String>,
    pub success: Option<String>,
}

#[derive(Serialize)]
pub struct StatusCounts {
    pub findings: usize,
    pub recommendations: usize,
    pub simulations: usize,
    pub audit: usize,
    pub channel_snapshots: usize,
}

pub async fn status(State(api): State<RiekoApi>) -> Result<Json<Status>, (StatusCode, String)> {
    // All SQLite reads run on the blocking pool, never on the Tokio executor,
    // so a large table cannot stall the runtime (RIEKO-AUDIT-014). Queries are
    // bounded aggregates (schema version, quick_check, COUNT(*), one row).
    let (schema_version, integrity_ok, counts, operational) =
        block_storage(api.state.storage.clone(), |s| {
            let schema = s.schema_version().map_err(|e| e.to_string())?;
            let integrity = s.integrity_check().is_ok();
            let counts = s.counts().map_err(|e| e.to_string())?;
            let op = s.read_operational_state().map_err(|e| e.to_string())?;
            Ok((schema, integrity, counts, op))
        })
        .await?;

    // An `execute`-feature build can mutate nodes; a build without it is
    // read-only. Capability is derived from the build, never claimed blindly.
    let read_only = cfg!(not(feature = "execute"));

    let (
        overall,
        source,
        source_data_at,
        last_ingestion,
        last_cycle,
        llm,
        alert_sink,
        cleanup,
        last_cleanup,
    ) = match operational.as_ref() {
        Some(state) => {
            let overall = rieko_status::assess(
                state,
                &rieko_status::HealthPolicy::default(),
                Utc::now(),
                integrity_ok,
            );
            (
                overall.as_str().to_string(),
                Some(source_label(state)),
                state.source_data_at.map(|t| t.to_rfc3339()),
                Some(OperationTimes {
                    attempt: state.last_ingestion_attempt.map(|t| t.to_rfc3339()),
                    success: state.last_ingestion_success.map(|t| t.to_rfc3339()),
                }),
                Some(OperationTimes {
                    attempt: state.last_cycle_attempt.map(|t| t.to_rfc3339()),
                    success: state.last_cycle_success.map(|t| t.to_rfc3339()),
                }),
                state.llm.as_str().to_string(),
                state.alert_sink.as_str().to_string(),
                state.cleanup.as_str().to_string(),
                Some(OperationTimes {
                    attempt: state.last_cleanup_attempt.map(|t| t.to_rfc3339()),
                    success: state.last_cleanup_success.map(|t| t.to_rfc3339()),
                }),
            )
        }
        None => {
            let overall = rieko_status::assess(
                &rieko_status::OperationalState::default(),
                &rieko_status::HealthPolicy::default(),
                Utc::now(),
                integrity_ok,
            );
            (
                overall.as_str().to_string(),
                None,
                None,
                None,
                None,
                "not_configured".into(),
                "not_configured".into(),
                "not_configured".into(),
                None,
            )
        }
    };

    Ok(Json(Status {
        engine: "rieko",
        version: VERSION,
        schema_version,
        read_only,
        integrity: if integrity_ok {
            "ok".to_string()
        } else {
            "failed".to_string()
        },
        overall,
        source,
        source_data_at,
        last_ingestion,
        last_cycle,
        llm,
        alert_sink,
        cleanup,
        last_cleanup,
        counts: StatusCounts {
            findings: counts.findings,
            recommendations: counts.recommendations,
            simulations: counts.simulations,
            audit: counts.audit,
            channel_snapshots: counts.channel_snapshots,
        },
    }))
}

fn source_label(state: &rieko_status::OperationalState) -> String {
    match state.source {
        rieko_status::SourceState::Fixture => "fixture".to_string(),
        rieko_status::SourceState::LndRest { connected } => {
            format!(
                "lnd-rest ({})",
                if connected {
                    "connected"
                } else {
                    "disconnected"
                }
            )
        }
    }
}

#[derive(Deserialize)]
pub struct LimitQuery {
    limit: Option<u32>,
    lifecycle: Option<String>,
}

#[derive(Deserialize)]
pub struct SnapshotQuery {
    limit: Option<u32>,
    network: Option<rieko_domain::BitcoinNetwork>,
    node_id: Option<String>,
}

fn limit(q: &LimitQuery) -> u32 {
    q.limit.unwrap_or(50).clamp(1, 500)
}

fn lifecycle(
    q: &LimitQuery,
) -> Result<rieko_findings::FindingLifecycleFilter, (StatusCode, String)> {
    match q.lifecycle.as_deref().unwrap_or("active") {
        "active" => Ok(rieko_findings::FindingLifecycleFilter::Active),
        "resolved" => Ok(rieko_findings::FindingLifecycleFilter::Resolved),
        "all" => Ok(rieko_findings::FindingLifecycleFilter::All),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "lifecycle must be active, resolved, or all".into(),
        )),
    }
}

pub async fn findings(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let lifecycle = lifecycle(&q)?;
    let rows = block_storage(api.state.storage.clone(), move |s| {
        s.latest_findings_by_lifecycle(limit(&q), lifecycle)
            .map_err(|e| e.to_string())
    })
    .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|f| serde_json::to_value(&f).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}

pub async fn findings_for_channel(
    State(api): State<RiekoApi>,
    Path(channel_id): Path<String>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let lifecycle = lifecycle(&q)?;
    let rows = block_storage(api.state.storage.clone(), move |s| {
        s.findings_for_channel_by_lifecycle(&channel_id, limit(&q), lifecycle)
            .map_err(|e| e.to_string())
    })
    .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|f| serde_json::to_value(&f).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}

pub async fn recommendations(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let rows = block_storage(api.state.storage.clone(), move |s| {
        s.latest_recommendations(limit(&q))
            .map_err(|e| e.to_string())
    })
    .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| serde_json::to_value(&r).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}

pub async fn audit(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let rows = block_storage(api.state.storage.clone(), move |s| {
        s.recent_audit(limit(&q)).map_err(|e| e.to_string())
    })
    .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|e| serde_json::to_value(&e).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}

#[cfg(feature = "simulate")]
pub async fn recent_simulations(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let rows = block_storage(api.state.storage.clone(), move |s| {
        s.recent_simulations(limit(&q)).map_err(|e| e.to_string())
    })
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|simulation| serde_json::to_value(simulation).unwrap_or(Value::Null))
            .collect(),
    ))
}

/// V2 simulation listing (ADR-0005). Returns replayable simulation records.
#[cfg(feature = "simulate")]
pub async fn recent_simulations_v2(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let rows = block_storage(api.state.storage.clone(), move |s| {
        s.recent_simulations_v2(limit(&q))
            .map_err(|e| e.to_string())
    })
    .await?;
    Ok(Json(rows.into_iter().map(simulation_value).collect()))
}

/// v2 simulation detail by ID.
#[cfg(feature = "simulate")]
pub async fn simulation_v2_by_id(
    State(api): State<RiekoApi>,
    Path(simulation_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let record = block_storage(api.state.storage.clone(), move |s| {
        s.simulation_v2_by_id(&simulation_id)
            .map_err(|e| e.to_string())
    })
    .await?;
    let rec = record.ok_or((StatusCode::NOT_FOUND, "simulation not found".into()))?;
    Ok(Json(simulation_value(rec)))
}

#[cfg(feature = "simulate")]
fn simulation_value(mut record: rieko_storage::SimulationRecord) -> Value {
    if record.status == "completed"
        && record
            .source_observed_at
            .as_deref()
            .is_some_and(|timestamp| {
                chrono::DateTime::parse_from_rfc3339(timestamp)
                    .map(|observed_at| {
                        chrono::Utc::now()
                            .signed_duration_since(observed_at.with_timezone(&chrono::Utc))
                            > chrono::Duration::minutes(15)
                    })
                    .unwrap_or(false)
            })
    {
        record.status = "stale".into();
    }
    serde_json::to_value(record).unwrap_or(Value::Null)
}

#[cfg(feature = "simulate")]
pub async fn simulation_views(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<SimulationView>>, (StatusCode, Json<SimulationErrorResponse>)> {
    let result = block_storage(api.state.storage.clone(), move |storage| {
        Ok(rieko_simulation_app::list_simulations(storage, limit(&q)))
    })
    .await
    .map_err(blocking_simulation_error)?;
    result
        .map(Json)
        .map_err(|error| simulation_error_response(simulation_error_status(error.kind), error))
}

#[cfg(feature = "simulate")]
pub async fn simulation_view_by_id(
    State(api): State<RiekoApi>,
    Path(simulation_id): Path<String>,
) -> Result<Json<SimulationView>, (StatusCode, Json<SimulationErrorResponse>)> {
    let requested_id = simulation_id.clone();
    let result = block_storage(api.state.storage.clone(), move |storage| {
        Ok(rieko_simulation_app::get_simulation(
            storage,
            &simulation_id,
        ))
    })
    .await
    .map_err(blocking_simulation_error)?;
    let simulation = result
        .map_err(|error| simulation_error_response(simulation_error_status(error.kind), error))?
        .ok_or_else(|| {
            simulation_error_response(
                StatusCode::NOT_FOUND,
                SimulationAppError {
                    kind: SimulationAppErrorKind::SimulationNotFound,
                    message: format!("no simulation with id {requested_id}"),
                    simulation: None,
                },
            )
        })?;
    Ok(Json(simulation))
}

#[cfg(feature = "simulate")]
pub async fn simulation_report_by_id(
    State(api): State<RiekoApi>,
    Path(simulation_id): Path<String>,
) -> Result<Json<rieko_simulation_app::SimulationReport>, (StatusCode, Json<SimulationErrorResponse>)>
{
    use crate::app::VERSION;
    use rieko_simulation_app::simulation_report;

    let requested_id = simulation_id.clone();
    let result = block_storage(api.state.storage.clone(), move |storage| {
        Ok(rieko_simulation_app::get_simulation(
            storage,
            &simulation_id,
        ))
    })
    .await
    .map_err(blocking_simulation_error)?;
    let simulation = result
        .map_err(|error| simulation_error_response(simulation_error_status(error.kind), error))?
        .ok_or_else(|| {
            simulation_error_response(
                StatusCode::NOT_FOUND,
                SimulationAppError {
                    kind: SimulationAppErrorKind::SimulationNotFound,
                    message: format!("no simulation with id {requested_id}"),
                    simulation: None,
                },
            )
        })?;
    Ok(Json(simulation_report(
        &simulation,
        VERSION,
        chrono::Utc::now(),
    )))
}

#[cfg(feature = "simulate")]
#[derive(Serialize)]
pub struct SimulationErrorResponse {
    error: SimulationErrorBody,
}

#[cfg(feature = "simulate")]
#[derive(Serialize)]
pub struct SimulationErrorBody {
    code: SimulationAppErrorKind,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    simulation: Option<Box<SimulationView>>,
}

#[cfg(feature = "simulate")]
pub async fn create_simulation_v2(
    State(api): State<RiekoApi>,
    request: Request,
) -> Result<(StatusCode, Json<CreateSimulationOutcome>), (StatusCode, Json<SimulationErrorResponse>)>
{
    let command = read_simulation_json(request).await?;
    let result = block_storage(api.state.storage.clone(), move |storage| {
        Ok(rieko_simulation_app::create_simulation(storage, command))
    })
    .await
    .map_err(blocking_simulation_error)?;
    match result {
        Ok(outcome) => Ok((
            if outcome.reused {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            Json(outcome),
        )),
        Err(error) => Err(simulation_error_response(
            simulation_error_status(error.kind),
            error,
        )),
    }
}

#[cfg(feature = "simulate")]
pub async fn compare_simulations_v2(
    State(api): State<RiekoApi>,
    payload: Result<Json<CompareSimulationsCommand>, JsonRejection>,
) -> Result<Json<SimulationComparison>, (StatusCode, Json<SimulationErrorResponse>)> {
    let Json(command) = payload.map_err(json_rejection_response)?;
    let result = block_storage(api.state.storage.clone(), move |storage| {
        Ok(rieko_simulation_app::compare_simulations(storage, command))
    })
    .await
    .map_err(blocking_simulation_error)?;
    result
        .map(Json)
        .map_err(|error| simulation_error_response(simulation_error_status(error.kind), error))
}

#[cfg(feature = "simulate")]
fn simulation_error_status(kind: SimulationAppErrorKind) -> StatusCode {
    match kind {
        SimulationAppErrorKind::RecommendationNotFound
        | SimulationAppErrorKind::FindingNotFound
        | SimulationAppErrorKind::SimulationNotFound
        | SimulationAppErrorKind::SnapshotNotFound => StatusCode::NOT_FOUND,
        SimulationAppErrorKind::FindingInactive | SimulationAppErrorKind::StaleInput => {
            StatusCode::CONFLICT
        }
        SimulationAppErrorKind::Storage | SimulationAppErrorKind::ModelFailure => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        SimulationAppErrorKind::IncompatibleSimulations => StatusCode::CONFLICT,
        _ => StatusCode::BAD_REQUEST,
    }
}

#[cfg(feature = "simulate")]
fn simulation_error_response(
    status: StatusCode,
    error: SimulationAppError,
) -> (StatusCode, Json<SimulationErrorResponse>) {
    (
        status,
        Json(SimulationErrorResponse {
            error: SimulationErrorBody {
                code: error.kind,
                message: error.message,
                simulation: error.simulation,
            },
        }),
    )
}

#[cfg(feature = "simulate")]
fn json_rejection_response(
    rejection: JsonRejection,
) -> (StatusCode, Json<SimulationErrorResponse>) {
    simulation_error_response(
        rejection.status(),
        SimulationAppError {
            kind: SimulationAppErrorKind::InvalidRequest,
            message: rejection.body_text(),
            simulation: None,
        },
    )
}

#[cfg(feature = "simulate")]
fn blocking_simulation_error(
    (status, message): (StatusCode, String),
) -> (StatusCode, Json<SimulationErrorResponse>) {
    simulation_error_response(
        status,
        SimulationAppError {
            kind: SimulationAppErrorKind::Storage,
            message,
            simulation: None,
        },
    )
}

#[cfg(feature = "simulate")]
async fn read_simulation_json<T: serde::de::DeserializeOwned>(
    request: Request,
) -> Result<T, (StatusCode, Json<SimulationErrorResponse>)> {
    let is_json = request
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(transport_simulation_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content type must be application/json",
        ));
    }
    let bytes = tokio::time::timeout(
        REQUEST_TIMEOUT,
        axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES),
    )
    .await
    .map_err(|_| transport_simulation_error(StatusCode::REQUEST_TIMEOUT, "request body timed out"))?
    .map_err(|error| {
        transport_simulation_error(StatusCode::PAYLOAD_TOO_LARGE, error.to_string())
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| transport_simulation_error(StatusCode::BAD_REQUEST, error.to_string()))
}

#[cfg(feature = "simulate")]
fn transport_simulation_error(
    status: StatusCode,
    message: impl Into<String>,
) -> (StatusCode, Json<SimulationErrorResponse>) {
    simulation_error_response(
        status,
        SimulationAppError {
            kind: SimulationAppErrorKind::InvalidRequest,
            message: message.into(),
            simulation: None,
        },
    )
}

/// Newest-first liquidity history across all channels.
pub async fn all_snapshots(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let rows = block_storage(api.state.storage.clone(), move |s| {
        s.recent_snapshots_all(limit(&q)).map_err(|e| e.to_string())
    })
    .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|s| serde_json::to_value(&s).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}

/// Newest-first liquidity history for one channel.
pub async fn channel_snapshots(
    State(api): State<RiekoApi>,
    Path(channel_id): Path<String>,
    Query(q): Query<SnapshotQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    if q.node_id.is_some() && q.network.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "node_id requires a network filter".into(),
        ));
    }
    let row_limit = q.limit.unwrap_or(50).clamp(1, 500);
    let rows = block_storage(api.state.storage.clone(), move |s| {
        match q.network {
            Some(network) => s.recent_channel_snapshots_for_network(
                network,
                q.node_id.as_deref(),
                &channel_id,
                row_limit,
            ),
            None => s.recent_channel_snapshots(&channel_id, row_limit),
        }
        .map_err(|e| e.to_string())
    })
    .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|s| serde_json::to_value(&s).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}
