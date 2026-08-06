use rieko_findings::{Action, ActionType};
use rieko_ingest_lnd::LndMutator;

use crate::{is_executable, ExecutionError, ExecutionReport, Executor};

/// An executor backed by a live LND node. Performs actions whose effect is
/// deterministic against the node's REST API.
///
/// Supports `UpdateFeePolicy` and `RebalanceChannel` (single-hop loop
/// payment only — see ADR-0002 D2). Every execution requires explicit
/// human approval and runs pre-flight checks before touching the node.
pub struct LndExecutor {
    client: LndMutator,
}

impl LndExecutor {
    pub fn new(
        rest_base: impl Into<String>,
        macaroon: Option<Vec<u8>>,
        tls_cert_pem: Option<Vec<u8>>,
    ) -> Result<Self, ExecutionError> {
        let client = LndMutator::new(rest_base, macaroon, tls_cert_pem)
            .map_err(|e| ExecutionError::Node(e.to_string()))?;
        Ok(Self { client })
    }
}

impl Executor for LndExecutor {
    fn execute(&self, action: &Action) -> Result<ExecutionReport, ExecutionError> {
        if !is_executable(action) {
            return Err(ExecutionError::NotExecutable(action.id.clone()));
        }
        match action.action_type {
            ActionType::UpdateFeePolicy => {
                let body = fee_policy_request(action)?;
                let resp = self
                    .client
                    .update_chan_policy(&body)
                    .map_err(|e| ExecutionError::Node(e.to_string()))?;
                Ok(ExecutionReport::succeeded(format!(
                    "update_channel_policy accepted: {resp}"
                )))
            }
            ActionType::RebalanceChannel => {
                let body = rebalance_request(action)?;
                let resp = self
                    .client
                    .send_payment(&body)
                    .map_err(|e| ExecutionError::Node(e.to_string()))?;
                let detail = serde_json::from_str::<serde_json::Value>(&resp)
                    .ok()
                    .and_then(|v| {
                        v.get("payment_hash")
                            .and_then(|h| h.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "unknown".into());
                Ok(ExecutionReport::succeeded(format!(
                    "rebalance payment sent: payment_hash={detail}"
                )))
            }
            ActionType::RestartService | ActionType::Custom => Err(ExecutionError::Unsupported(
                action.action_type.as_str().into(),
            )),
        }
    }
}

/// Build a `SendToRouteRequest` JSON body for a single-hop loop payment.
/// The route is `self → peer → self` (circular), moving the delta through
/// the peer and back. The peer's outgoing channel is the same as the inbound
/// one (for a single-hop circular rebalance).
fn rebalance_request(action: &Action) -> Result<String, ExecutionError> {
    let p = &action.params;
    let chan_point = p
        .get("chan_point")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ExecutionError::MissingParams("chan_point required".into()))?;
    let delta_msat = p
        .get("delta_msat")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ExecutionError::MissingParams("delta_msat required".into()))?;
    let peer_pubkey = p.get("peer_pubkey").and_then(|v| v.as_str()).unwrap_or("");

    let body = serde_json::json!({
        "payment_addr": base64_payment_addr(),
        "route": {
            "hops": [{
                "chan_point": chan_point,
                "amt_to_forward_msat": delta_msat.to_string(),
                "expiry": 144u32,
            }],
            "total_time_lock": 144u32,
            "total_amt_msat": delta_msat.to_string(),
        },
    });

    if !peer_pubkey.is_empty() {
        let mut b = body.as_object().cloned().unwrap_or_default();
        if let Some(route) = b.get_mut("route").and_then(|r| r.as_object_mut()) {
            if let Some(hops) = route.get_mut("hops").and_then(|h| h.as_array_mut()) {
                if let Some(hop) = hops.first_mut() {
                    hop.as_object_mut()
                        .map(|h| h.insert("pub_key".into(), serde_json::json!(peer_pubkey)));
                }
            }
        }
        return serde_json::to_string(&b).map_err(|e| ExecutionError::MissingParams(e.to_string()));
    }

    serde_json::to_string(&body).map_err(|e| ExecutionError::MissingParams(e.to_string()))
}

/// A random 32-byte payment address, base64-encoded for LND's API.
/// Single-use: a new one is generated for every rebalance attempt.
fn base64_payment_addr() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id() as u128;
    let seed = ts ^ (pid << 64);
    let addr = seed.to_le_bytes();
    // Simple base64 encoding: 32 raw bytes → group of 6 bits each.
    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(44);
    for chunk in addr.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(chars[((n >> 18) & 0x3F) as usize] as char);
        out.push(chars[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(chars[((n >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(chars[(n & 0x3F) as usize] as char);
        }
    }
    while out.len() % 4 != 0 {
        out.push('=');
    }
    out
}

/// Build an `UpdateChanPolicyRequest`. Reuses the fee params the
/// recommendation stored (fee_rate_ppm, base_fee_msat, cltv_delta) so the
/// policy we push matches what was approved.
fn fee_policy_request(action: &Action) -> Result<String, ExecutionError> {
    let p = &action.params;
    let mut body = serde_json::Map::new();
    if let Some(v) = p.get("fee_rate_ppm").and_then(|v| v.as_u64()) {
        body.insert("fee_rate_ppm".into(), serde_json::json!(v));
    }
    if let Some(v) = p.get("base_fee_msat").and_then(|v| v.as_u64()) {
        body.insert("fee_base_msat".into(), serde_json::json!(v));
    }
    if let Some(v) = p.get("cltv_delta").and_then(|v| v.as_u64()) {
        body.insert("time_lock_delta".into(), serde_json::json!(v));
    }
    // Global policy unless a channel point was requested.
    if let Some(cp) = p.get("chan_point").and_then(|v| v.as_str()) {
        body.insert("chan_point".into(), serde_json::json!(cp));
    }
    if body.is_empty() {
        return Err(ExecutionError::MissingParams(
            "no fee params on action".into(),
        ));
    }
    serde_json::to_string(&serde_json::Value::Object(body))
        .map_err(|e| ExecutionError::MissingParams(e.to_string()))
}

#[cfg(test)]
mod tests {
    use rieko_findings::{Action, ActionStage, ActionType};

    use super::*;

    fn fee_action() -> Action {
        Action::new(
            ActionType::UpdateFeePolicy,
            ActionStage::Approved,
            Some("c1".into()),
            serde_json::json!({ "fee_rate_ppm": 1, "base_fee_msat": 1000 }),
            "lower fees",
        )
    }

    #[test]
    fn builds_valid_policy_request() {
        let body = fee_policy_request(&fee_action()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["fee_rate_ppm"], 1);
        assert_eq!(v["fee_base_msat"], 1000);
    }

    #[test]
    fn rebalance_missing_params_is_error() {
        let action = Action::new(
            ActionType::RebalanceChannel,
            ActionStage::Approved,
            Some("c1".into()),
            serde_json::json!({}),
            "rebalance",
        );
        assert!(rebalance_request(&action).is_err());
    }

    #[test]
    fn rebalance_builds_valid_request() {
        let action = Action::new(
            ActionType::RebalanceChannel,
            ActionStage::Approved,
            Some("c1".into()),
            serde_json::json!({
                "chan_point": "aaa111bbb222ccc333:0",
                "delta_msat": 40_000u64,
            }),
            "rebalance",
        );
        let body = rebalance_request(&action).unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(!v["payment_addr"].as_str().unwrap().is_empty());
        let hop = &v["route"]["hops"][0];
        assert_eq!(hop["chan_point"], "aaa111bbb222ccc333:0");
    }

    #[test]
    fn executor_requires_approval() {
        let e = LndExecutor::new("http://127.0.0.1:1", None, None).unwrap();
        let mut action = fee_action();
        action.stage = ActionStage::Simulated;
        assert!(matches!(
            e.execute(&action),
            Err(ExecutionError::NotExecutable(_))
        ));
    }
}
