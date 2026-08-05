use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::app::VERSION;
use crate::RiekoApi;

#[derive(Serialize)]
pub struct Status {
    pub engine: &'static str,
    pub version: &'static str,
    pub read_only: bool,
    pub counts: StatusCounts,
}

#[derive(Serialize)]
pub struct StatusCounts {
    pub findings: usize,
    pub findings_by_severity: std::collections::BTreeMap<String, usize>,
    pub recommendations: usize,
    pub recommendations_by_stage: std::collections::BTreeMap<String, usize>,
    pub simulations: usize,
    pub audit: usize,
    pub channel_snapshots: usize,
}

pub async fn status(State(api): State<RiekoApi>) -> Result<Json<Status>, (StatusCode, String)> {
    let mut storage = api
        .state
        .storage
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;
    let findings = storage.latest_findings(1_000_000).map_err(api_err)?;
    let recommendations = storage.latest_recommendations(1_000_000).map_err(api_err)?;
    let simulations = storage.recent_simulations(1_000_000).map_err(api_err)?;
    let audit = storage.recent_audit(1_000_000).map_err(api_err)?;
    let snapshots = storage.recent_snapshots_all(1_000_000).map_err(api_err)?;

    let mut findings_by_severity = std::collections::BTreeMap::new();
    for f in &findings {
        *findings_by_severity
            .entry(format!("{:?}", f.severity))
            .or_insert(0) += 1;
    }
    let mut recommendations_by_stage = std::collections::BTreeMap::new();
    for r in &recommendations {
        *recommendations_by_stage
            .entry(format!("{:?}", r.action.stage))
            .or_insert(0) += 1;
    }

    Ok(Json(Status {
        engine: "rieko",
        version: VERSION,
        read_only: true,
        counts: StatusCounts {
            findings: findings.len(),
            findings_by_severity,
            recommendations: recommendations.len(),
            recommendations_by_stage,
            simulations: simulations.len(),
            audit: audit.len(),
            channel_snapshots: snapshots.len(),
        },
    }))
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
    let mut storage = api
        .state
        .storage
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;
    let rows = storage.latest_findings(limit(&q)).map_err(api_err)?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|f| serde_json::to_value(&f).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}

pub async fn findings_for_channel(
    State(api): State<RiekoApi>,
    Path(channel_id): Path<String>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let mut storage = api
        .state
        .storage
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;
    let rows = storage.findings_for_channel(&channel_id).map_err(api_err)?;
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
    let mut storage = api
        .state
        .storage
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;
    let rows = storage.latest_recommendations(limit(&q)).map_err(api_err)?;
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
    let mut storage = api
        .state
        .storage
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;
    let rows = storage.recent_audit(limit(&q)).map_err(api_err)?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|e| serde_json::to_value(&e).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}

#[cfg(feature = "future")]
pub async fn recent_simulations(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let mut storage = api
        .state
        .storage
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;
    let rows = storage.recent_simulations(limit(&q)).map_err(api_err)?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|s| serde_json::to_value(&s).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}

/// Newest-first liquidity history across all channels.
pub async fn all_snapshots(
    State(api): State<RiekoApi>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<Value>>, (StatusCode, String)> {
    let mut storage = api
        .state
        .storage
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;
    let rows = storage.recent_snapshots_all(limit(&q)).map_err(api_err)?;
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
    let mut storage = api
        .state
        .storage
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;
    let rows = storage
        .recent_channel_snapshots(&channel_id, limit(&q))
        .map_err(api_err)?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|s| serde_json::to_value(&s).unwrap_or(Value::Null))
        .collect();
    Ok(Json(out))
}

fn api_err(e: rieko_storage::StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
