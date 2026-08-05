use rieko_findings::{
    Action, ActionStage, ActionType, Finding, Recommendation, Severity,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RecommendationEngineError {
    #[error("cannot recommend for finding {0}: unsupported detector")]
    UnsupportedDetector(String),
    #[error("cannot recommend for finding {0}: no target channel")]
    MissingChannel(String),
}

/// Maps findings to concrete actions. v1: every action is created at
/// `Recommended` stage and written to the audit log (D7). The mapping itself
/// is deterministic rules — LLMs never generate actions.
pub struct RecommendationEngine;

impl RecommendationEngine {
    pub fn recommend(&self, finding: &Finding) -> Result<Vec<Recommendation>, RecommendationEngineError> {
        match finding.detector.as_str() {
            "channel_liquidity" => self.recommend_liquidity(finding),
            other => Err(RecommendationEngineError::UnsupportedDetector(other.to_string())),
        }
    }

    fn recommend_liquidity(&self, finding: &Finding) -> Result<Vec<Recommendation>, RecommendationEngineError> {
        let channel = finding
            .channel
            .clone()
            .ok_or_else(|| RecommendationEngineError::MissingChannel(finding.id.clone()))?;

        let direction = finding
            .evidence_value("direction")
            .and_then(|v| v.as_str())
            .unwrap_or("outbound");

        let mut out = Vec::new();
        match direction {
            "outbound" => out.push(Recommendation {
                finding_id: finding.id.clone(),
                action: Action::new(
                    ActionType::RebalanceChannel,
                    ActionStage::Recommended,
                    Some(channel.clone()),
                    serde_json::json!({
                        "reason": "outbound liquidity drained",
                        "desired_ratio": 0.5,
                        "method": "splice-in or payment-rebalance",
                    }),
                    format!("Rebalance channel {channel}: outbound capacity is low"),
                ),
            }),
            "inbound" => {
                out.push(Recommendation {
                    finding_id: finding.id.clone(),
                    action: Action::new(
                        ActionType::UpdateFeePolicy,
                        ActionStage::Recommended,
                        Some(channel.clone()),
serde_json::json!({
                        "reason": "inbound liquidity drained",
                        "suggested": "reduce fee_rate_ppm to attract inbound liquidity",
                        "fee_rate_ppm": 1,
                        "base_fee_msat": 0,
                        "cltv_delta": 40,
                    }),
                        format!("Lower fees on channel {channel} to attract inbound liquidity"),
                    ),
                });
                if finding.severity >= Severity::Warning {
                    out.push(Recommendation {
                        finding_id: finding.id.clone(),
                        action: Action::new(
                            ActionType::RebalanceChannel,
                            ActionStage::Recommended,
                            Some(channel),
                            serde_json::json!({
                                "reason": "inbound liquidity drained",
                                "desired_ratio": 0.5,
                                "method": "splice-out",
                            }),
                            "Splice out from this channel to restore 50/50 balance",
                        ),
                    });
                }
            }
            _ => {}
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use rieko_findings::{Evidence, Severity};

    use super::*;

    fn finding(channel: &str, direction: &str, severity: Severity) -> Finding {
        Finding {
            id: "f1".into(),
            detector: "channel_liquidity".into(),
            severity,
            node: Some("local-node".into()),
            channel: Some(channel.into()),
            evidence: vec![Evidence::text("direction", direction)],
            explanation: None,
            timestamp: chrono::Utc::now(),
        }
    }

    #[test]
    fn outbound_suggests_rebalance() {
        let engine = RecommendationEngine;
        let recs = engine
            .recommend(&finding("c1", "outbound", Severity::Warning))
            .unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].action.action_type, ActionType::RebalanceChannel);
        assert_eq!(recs[0].action.stage, ActionStage::Recommended);
        assert_eq!(recs[0].action.target.as_deref(), Some("c1"));
    }

    #[test]
    fn inbound_suggests_fee_change_and_rebalance() {
        let engine = RecommendationEngine;
        let recs = engine
            .recommend(&finding("c1", "inbound", Severity::Warning))
            .unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].action.action_type, ActionType::UpdateFeePolicy);
    }

    #[test]
    fn unknown_detector_is_rejected() {
        let engine = RecommendationEngine;
        let mut f = finding("c1", "outbound", Severity::Warning);
        f.detector = "magic".into();
        assert!(engine.recommend(&f).is_err());
    }
}
