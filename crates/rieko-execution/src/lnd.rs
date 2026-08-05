use rieko_findings::{Action, ActionType};
use rieko_ingest_lnd::LndClient;

use crate::{is_executable, ExecutionError, ExecutionReport, Executor};

/// An executor backed by a live LND node. Performs actions whose effect is
/// deterministic against the node's REST API.
///
/// `UpdateFeePolicy` is supported today: it maps cleanly onto `PUT
/// /v1/chanpolicy`. `RebalanceChannel` is intentionally *not* performed
/// here — a payment-rebalance moves funds between peers and needs careful
/// routing knowledge, so it fails loudly rather than pretending. That keeps
/// the honest default (D7: explicit human approval, deterministic actions)
/// without mutating a node in a way we can't reason about.
pub struct LndExecutor {
    client: LndClient,
}

impl LndExecutor {
    pub fn new(rest_base: impl Into<String>, macaroon: Option<String>) -> Self {
        Self {
            client: LndClient::new(rest_base, macaroon),
        }
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
            ActionType::RebalanceChannel => Err(ExecutionError::Unsupported(
                "rebalance_channel has no node-backed executor yet".into(),
            )),
            ActionType::RestartService | ActionType::Custom => Err(ExecutionError::Unsupported(
                action.action_type.as_str().into(),
            )),
        }
    }
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
    fn unsupported_rebalance_is_loud() {
        let e = LndExecutor::new("http://127.0.0.1:1", None);
        let action = Action::new(
            ActionType::RebalanceChannel,
            ActionStage::Approved,
            Some("c1".into()),
            serde_json::json!({ "desired_ratio": 0.5 }),
            "rebalance",
        );
        assert!(matches!(
            e.execute(&action),
            Err(ExecutionError::Unsupported(_))
        ));
    }

    #[test]
    fn executor_requires_approval() {
        let e = LndExecutor::new("http://127.0.0.1:1", None);
        let mut action = fee_action();
        action.stage = ActionStage::Simulated;
        assert!(matches!(
            e.execute(&action),
            Err(ExecutionError::NotExecutable(_))
        ));
    }
}
