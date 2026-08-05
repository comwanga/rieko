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
}

pub async fn status(State(_api): State<RiekoApi>) -> Json<Status> {
    Json(Status {
        engine: "rieko",
        version: VERSION,
        read_only: true,
    })
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
    let rows = storage
        .latest_findings(limit(&q))
        .map_err(api_err)?;
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
    let rows = storage
        .findings_for_channel(&channel_id)
        .map_err(api_err)?;
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
    let rows = storage
        .latest_recommendations(limit(&q))
        .map_err(api_err)?;
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
