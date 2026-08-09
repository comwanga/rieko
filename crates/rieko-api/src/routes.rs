use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::app::{block_read, VERSION};
use crate::RiekoApi;

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
        block_read(api.state.storage.clone(), |s| {
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
}

fn limit(q: &LimitQuery) -> u32 {
    q.limit.unwrap_or(50).clamp(1, 500)
}

pub async fn findings(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let rows = block_read(api.state.storage.clone(), move |s| {
        s.latest_findings(limit(&q)).map_err(|e| e.to_string())
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
    let rows = block_read(api.state.storage.clone(), move |s| {
        s.findings_for_channel(&channel_id, limit(&q))
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
    let rows = block_read(api.state.storage.clone(), move |s| {
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
    let rows = block_read(api.state.storage.clone(), move |s| {
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
    let rows = block_read(api.state.storage.clone(), move |s| {
        s.recent_simulations(limit(&q)).map_err(|e| e.to_string())
    })
    .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|s| serde_json::to_value(&s).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}

/// v2 simulation listing (ADR-0005). Returns SimulationRecords with full metadata.
#[cfg(feature = "simulate")]
pub async fn recent_simulations_v2(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let rows = block_read(api.state.storage.clone(), move |s| {
        s.recent_simulations_v2(limit(&q))
            .map_err(|e| e.to_string())
    })
    .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| serde_json::to_value(&r).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}

/// v2 simulation detail by ID.
#[cfg(feature = "simulate")]
pub async fn simulation_v2_by_id(
    State(api): State<RiekoApi>,
    Path(simulation_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let rows = block_read(api.state.storage.clone(), move |s| {
        s.recent_simulations_v2(1000).map_err(|e| e.to_string())
    })
    .await?;
    let rec = rows
        .into_iter()
        .find(|r| r.id == simulation_id)
        .ok_or((StatusCode::NOT_FOUND, "simulation not found".into()))?;
    let v = serde_json::to_value(&rec)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(v))
}

/// Newest-first liquidity history across all channels.
pub async fn all_snapshots(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let rows = block_read(api.state.storage.clone(), move |s| {
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
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let rows = block_read(api.state.storage.clone(), move |s| {
        s.recent_channel_snapshots(&channel_id, limit(&q))
            .map_err(|e| e.to_string())
    })
    .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|s| serde_json::to_value(&s).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}
