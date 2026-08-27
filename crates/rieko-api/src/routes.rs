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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub engine: String,
    pub version: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationTimes {
    pub attempt: Option<String>,
    pub success: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusCounts {
    pub findings: usize,
    pub recommendations: usize,
    pub simulations: usize,
    pub audit: usize,
    pub channel_snapshots: usize,
    pub simulation_completed: usize,
    pub simulation_failed: usize,
    pub simulation_stale: usize,
}

/// Read-only projection of the latest persisted Lightning observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightningInspection {
    pub state: Option<rieko_status::LightningState>,
}

/// Read-only projection of the latest persisted Bitcoin Core observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinInspection {
    pub state: Option<rieko_status::BitcoinCoreState>,
}

/// Read-only projection of the persisted BTCPay operational fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcPayInspection {
    pub state: Option<BtcPayInspectionState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcPayInspectionState {
    pub source: rieko_status::SourceState,
    pub last_attempt: Option<chrono::DateTime<Utc>>,
    pub last_success: Option<chrono::DateTime<Utc>>,
    pub source_data_at: Option<chrono::DateTime<Utc>>,
}

pub async fn inspect_btcpay(
    State(api): State<RiekoApi>,
) -> Result<Json<BtcPayInspection>, (StatusCode, String)> {
    let state = block_storage(api.state.storage.clone(), |storage| {
        storage
            .read_operational_state()
            .map(|state| {
                state.map(|state| BtcPayInspectionState {
                    source: state.source,
                    last_attempt: state.last_ingestion_attempt,
                    last_success: state.last_ingestion_success,
                    source_data_at: state.source_data_at,
                })
            })
            .map_err(|error| error.to_string())
    })
    .await?;
    Ok(Json(BtcPayInspection { state }))
}

pub async fn inspect_bitcoin(
    State(api): State<RiekoApi>,
) -> Result<Json<BitcoinInspection>, (StatusCode, String)> {
    let state = block_storage(api.state.storage.clone(), |storage| {
        storage
            .read_operational_state()
            .map(|state| state.and_then(|state| state.bitcoin_core))
            .map_err(|error| error.to_string())
    })
    .await?;
    Ok(Json(BitcoinInspection { state }))
}

pub async fn inspect_lightning(
    State(api): State<RiekoApi>,
) -> Result<Json<LightningInspection>, (StatusCode, String)> {
    let state = block_storage(api.state.storage.clone(), |storage| {
        storage
            .read_operational_state()
            .map(|state| state.and_then(|state| state.lightning))
            .map_err(|error| error.to_string())
    })
    .await?;
    Ok(Json(LightningInspection { state }))
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
        engine: "rieko".into(),
        version: VERSION.into(),
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
            simulation_completed: counts.simulation_counts.completed,
            simulation_failed: counts.simulation_counts.failed,
            simulation_stale: counts.simulation_counts.stale,
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
        rieko_status::SourceState::BtcPayGreenfield { connected } => {
            format!(
                "btcpay-greenfield ({})",
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

fn recommendation_history(q: &LimitQuery) -> bool {
    q.lifecycle.as_deref() == Some("all")
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

pub async fn finding_by_id(
    State(api): State<RiekoApi>,
    Path(finding_id): Path<String>,
) -> Result<Json<rieko_findings::Finding>, (StatusCode, String)> {
    let requested_id = finding_id.clone();
    let finding = block_storage(api.state.storage.clone(), move |storage| {
        storage
            .finding_by_id(&finding_id)
            .map_err(|error| error.to_string())
    })
    .await?;
    finding.map(Json).ok_or((
        StatusCode::NOT_FOUND,
        format!("finding {requested_id} not found"),
    ))
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
    let include_history = recommendation_history(&q);
    let rows = block_storage(api.state.storage.clone(), move |s| {
        if include_history {
            s.latest_recommendations(limit(&q))
        } else {
            // Preserve the existing default: resolved recommendations remain
            // archived unless a caller explicitly requests history.
            s.latest_active_recommendations(limit(&q))
        }
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
    api.state
        .check_simulation_rate()
        .await
        .map_err(|(status, message)| transport_simulation_error(status, message))?;
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

/// Webhook ingestion endpoint for BTCPay Server Greenfield notifications.
///
/// Processing pipeline:
/// 1. Body-size enforcement (1MB max via Axum middleware).
/// 2. HMAC-SHA256 signature verification (`BTCPay-Sig: sha256=<64 hex chars>`).
/// 3. Payload deserialization and delivery identity extraction (`deliveryId` / `originalDeliveryId`).
/// 4. Deduplication check against persistent storage (acknowledged as `already_processed` without re-queueing).
/// 5. Normalization into strongly-typed `NodeEvent`.
/// 6. Atomic persistence of delivery identity and the normalized event.
/// 7. Best-effort bounded wake-up of the agent worker; durable replay is authoritative.
pub async fn btcpay_webhook(
    State(api): State<RiekoApi>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl axum::response::IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    use rieko_ingest_btcpay::{
        normalize_webhook_payload, verify_btcpay_sig, BtcPayWebhookEvent, BTCPAY_SIG_HEADER,
    };

    // 1. Signature Verification (HMAC-SHA256 constant-time). The public route
    // exists on every API instance, but it must fail closed until the runtime
    // explicitly configures both its secret and event consumer.
    let Some(secret) = api.state.btcpay_webhook_secret.as_deref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "code": "integration_not_configured",
                    "message": "BTCPay webhook ingestion is not configured"
                }
            })),
        ));
    };
    let sig = headers
        .get(BTCPAY_SIG_HEADER)
        .or_else(|| headers.get("btcpay-sig"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if !verify_btcpay_sig(secret.as_bytes(), &body, sig) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": {
                    "code": "invalid_signature",
                    "message": "BTCPay-Sig HMAC-SHA256 signature verification failed"
                }
            })),
        ));
    }

    // 2. Extract delivery envelope and identity
    let envelope: BtcPayWebhookEvent = serde_json::from_slice(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "code": "invalid_payload",
                    "message": e.to_string()
                }
            })),
        )
    })?;

    let fallback_delivery_id =
        (!envelope.delivery_id.is_empty()).then_some(envelope.delivery_id.as_str());
    let canonical_delivery_id = envelope
        .original_delivery_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(fallback_delivery_id);
    let canonical_delivery_id = canonical_delivery_id.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "code": "invalid_payload",
                    "message": "deliveryId or originalDeliveryId is required"
                }
            })),
        )
    })?;

    // 3. Deduplication check against persistent storage
    let is_already_processed = {
        let mut storage = api.state.storage.lock().await;
        storage
            .is_webhook_delivery_processed(canonical_delivery_id)
            .unwrap_or(false)
    };

    if is_already_processed {
        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "already_processed",
                "delivery_id": canonical_delivery_id
            })),
        ));
    }

    // 4. Normalization into strongly-typed domain event
    let event = normalize_webhook_payload(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "code": "normalization_failed",
                    "message": e.to_string()
                }
            })),
        )
    })?;

    // 5. Durably hand the normalized event to the agent before acknowledging.
    let delivery_id = canonical_delivery_id.to_string();
    let webhook_id = envelope.webhook_id.clone();
    let event_type = envelope.event_type.clone();
    let durable_event = event.clone();
    block_storage(api.state.storage.clone(), move |storage| {
        storage
            .enqueue_webhook_event(
                &delivery_id,
                Some(&webhook_id),
                Some(&event_type),
                &durable_event,
                chrono::Utc::now(),
            )
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|(_, message)| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": {
                    "code": "persistence_failed",
                    "message": message
                }
            })),
        )
    })?;

    // 6. Best-effort wake-up. A full or closed channel cannot lose the event:
    // the worker drains durable pending rows on its next wake-up or restart.
    if let Some(sender) = &api.state.event_sender {
        if let Err(error) = sender.try_send(event) {
            tracing::warn!(%error, %canonical_delivery_id, "BTCPay event persisted; worker wake-up deferred");
        }
    }

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "accepted",
            "delivery_id": canonical_delivery_id
        })),
    ))
}
