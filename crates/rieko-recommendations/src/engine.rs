use rieko_findings::{
    Action, ActionType, Actionability, Finding, Rationale, Recommendation, Severity,
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
/// `Recommended` stage, carries NO execution parameters, and is accompanied by
/// a deterministic, evidence-backed rationale. LLMs never generate actions or
/// parameters (RIEKO-AUDIT-010).
pub struct RecommendationEngine;

impl RecommendationEngine {
    pub fn recommend(
        &self,
        finding: &Finding,
    ) -> Result<Vec<Recommendation>, RecommendationEngineError> {
        match finding.detector.as_str() {
            "channel_liquidity" => self.recommend_liquidity(finding),
            other => Err(RecommendationEngineError::UnsupportedDetector(
                other.to_string(),
            )),
        }
    }

    fn recommend_liquidity(
        &self,
        finding: &Finding,
    ) -> Result<Vec<Recommendation>, RecommendationEngineError> {
        let channel = finding
            .channel
            .clone()
            .ok_or_else(|| RecommendationEngineError::MissingChannel(finding.id.clone()))?;

        let direction = finding
            .evidence_value("direction")
            .and_then(|v| v.as_str())
            .unwrap_or("outbound");

        // Evidence extracted from the finding, never invented. Only numbers
        // presented are those already in the evidence.
        let evidence_refs: Vec<String> = finding
            .evidence
            .iter()
            .map(|e| format!("{}={}", e.key, e.value))
            .collect();

        let mut out = Vec::new();
        match direction {
            "outbound" => out.push(build_rebased_review(
                finding,
                channel.clone(),
                "outbound",
                &evidence_refs,
            )),
            "inbound" => {
                out.push(build_fee_review(
                    finding,
                    &channel,
                    "inbound",
                    &evidence_refs,
                ));
                if finding.severity >= Severity::Warning {
                    out.push(build_rebased_review(
                        finding,
                        channel,
                        "inbound",
                        &evidence_refs,
                    ));
                }
            }
            _ => {}
        }
        Ok(out)
    }
}

/// A deliberately modest, evidence-backed rebalance review. It never names a
/// target ratio or a specific method, and it carries no mutation parameters:
/// rebalancing advice stops at operator decision support (RIEKO-AUDIT-010).
fn build_rebased_review(
    finding: &Finding,
    channel: String,
    direction: &str,
    evidence: &[String],
) -> Recommendation {
    Recommendation {
        finding_id: finding.id.clone(),
        action: Action::for_recommendation(
            &finding.id,
            ActionType::RebalanceChannel,
            Some(channel.clone()),
            serde_json::json!({
                "reason": format!("{direction} liquidity drained"),
            }),
            format!(
                "Review the intended role of channel {channel} before considering a rebalance."
            ),
        ),
        rationale: Rationale {
            evidence: evidence.to_vec(),
            preconditions: vec![
                format!("Confirm channel {channel} is meant to route in the {direction} direction."),
                "Confirm the imbalance is expected rather than a fault.".into(),
                "Validate rebalancing cost and routing strategy before any action.".into(),
            ],
            expected_effect: "If rebalancing is warranted, restoring the local balance could let the channel route payments in the drained direction again."
                .into(),
            risks: vec![
                "Rebalancing consumes on-chain fees and may not improve routing if demand is one-directional.".into(),
                "Moving liquidity can reduce availability on the opposite side.".into(),
            ],
            limitations: vec![
                "The analysis is based on a single liquidity snapshot, not routing history.".into(),
                "No fee or routing-cost model was used; the benefit of rebalancing is unquantified.".into(),
            ],
            actionability: Actionability::OperatorActionable,
        },
    }
}

/// A modest, evidence-backed fee-policy review. Recommends investigating, never
/// a specific numeric fee: Rieko has no evidence justifying any particular
/// `fee_rate` / `base_fee` / `cltv_delta` value (RIEKO-AUDIT-010).
fn build_fee_review(
    finding: &Finding,
    channel: &str,
    direction: &str,
    evidence: &[String],
) -> Recommendation {
    Recommendation {
        finding_id: finding.id.clone(),
        action: Action::for_recommendation(
            &finding.id,
            ActionType::UpdateFeePolicy,
            Some(channel.to_string()),
            serde_json::json!({
                "reason": format!("{direction} liquidity drained"),
            }),
            format!("Review the fee policy on channel {channel} to understand inbound demand."),
        ),
        rationale: Rationale {
            evidence: evidence.to_vec(),
            preconditions: vec![
                "Inspect recent forwarding direction and demand for this channel.".into(),
                "Compare the current fee policy against operator policy before changing anything."
                    .into(),
            ],
            expected_effect: "Identifying the fee policy's role in inbound liquidity lets the operator make an informed, cost-aware decision."
                .into(),
            risks: vec![
                "Lowering fees without demand evidence may reduce routing revenue for no benefit."
                    .into(),
                "A universal fee change is not justified by a single channel's balance.".into(),
            ],
            limitations: vec![
                "No fee optimization or routing-intelligence model exists; specific fee values are not recommended.".into(),
            ],
            actionability: Actionability::OperatorActionable,
        },
    }
}

#[cfg(test)]
mod tests {
    use rieko_findings::{ActionStage, ActionType, Evidence, Severity};

    use super::*;

    fn finding(channel: &str, direction: &str, severity: Severity) -> Finding {
        let now = chrono::Utc::now();
        Finding {
            id: "f1".into(),
            detector: "channel_liquidity".into(),
            detector_version: "1".into(),
            schema_version: rieko_findings::FINDING_SCHEMA_VERSION,
            severity,
            node: Some("local-node".into()),
            channel: Some(channel.into()),
            evidence: vec![
                Evidence::text("direction", direction),
                Evidence::number("local_ratio", 0.1),
                Evidence::number("capacity_msat", 1_000_000.0),
            ],
            explanation: None,
            timestamp: now,
            first_seen_at: now,
            last_seen_at: now,
            lifecycle: rieko_findings::FindingLifecycle::Active,
        }
    }

    #[test]
    fn outbound_suggests_a_modest_rebalance_review() {
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
    fn inbound_suggests_fee_review_and_rebalance_review() {
        let engine = RecommendationEngine;
        let recs = engine
            .recommend(&finding("c1", "inbound", Severity::Warning))
            .unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].action.action_type, ActionType::UpdateFeePolicy);
        assert_eq!(recs[1].action.action_type, ActionType::RebalanceChannel);
    }

    #[test]
    fn unknown_detector_is_rejected() {
        let engine = RecommendationEngine;
        let mut f = finding("c1", "outbound", Severity::Warning);
        f.detector = "magic".into();
        assert!(engine.recommend(&f).is_err());
    }

    // --- RIEKO-AUDIT-010 required tests ---

    #[test]
    fn same_finding_produces_same_recommendation() {
        let engine = RecommendationEngine;
        let f = finding("c1", "outbound", Severity::Warning);
        let a = engine.recommend(&f).unwrap();
        let b = engine.recommend(&f).unwrap();
        // Id, type, target, params, summary and rationale must be stable; the
        // wall-clock `created_at` stamps naturally differ between calls.
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.action.id, y.action.id);
            assert_eq!(x.action.action_type, y.action.action_type);
            assert_eq!(x.action.target, y.action.target);
            assert_eq!(x.action.params, y.action.params);
            assert_eq!(x.action.summary, y.action.summary);
            assert_eq!(x.rationale, y.rationale);
        }
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn no_unsupported_mutation_parameter_appears() {
        let engine = RecommendationEngine;
        for direction in ["outbound", "inbound"] {
            for severity in [Severity::Warning, Severity::Critical] {
                let recs = engine
                    .recommend(&finding("c1", direction, severity))
                    .unwrap();
                for rec in recs {
                    let params = &rec.action.params;
                    for banned in [
                        "desired_ratio",
                        "fee_rate_ppm",
                        "base_fee_msat",
                        "cltv_delta",
                        "method",
                        "chan_point",
                    ] {
                        assert!(
                            params.get(banned).is_none(),
                            "banned mutation parameter {banned} in {params}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn recommendation_preserves_finding_provenance() {
        let engine = RecommendationEngine;
        let f = finding("c1", "outbound", Severity::Warning);
        let recs = engine.recommend(&f).unwrap();
        for rec in recs {
            assert_eq!(rec.finding_id, f.id);
            assert_eq!(rec.action.stage, ActionStage::Recommended);
        }
    }

    #[test]
    fn critical_severity_does_not_generate_executable_advice() {
        let engine = RecommendationEngine;
        let recs = engine
            .recommend(&finding("c1", "inbound", Severity::Critical))
            .unwrap();
        // Critical findings still yield reviews, never numeric execution params.
        assert_eq!(recs.len(), 2);
        for rec in &recs {
            let params = &rec.action.params;
            assert!(
                params.as_object().map(|m| m.is_empty()).unwrap_or(true)
                    || params["reason"].is_string(),
                "only descriptive reason is allowed, got {params}"
            );
            assert!(
                params["desired_ratio"].is_null() && params["fee_rate_ppm"].is_null(),
                "no executable target in {params}"
            );
        }
    }

    #[test]
    fn llm_disabled_yields_a_complete_structured_recommendation() {
        // The engine never consults an LLM; every recommendation carries the
        // full rationale regardless.
        let engine = RecommendationEngine;
        let recs = engine
            .recommend(&finding("c1", "outbound", Severity::Warning))
            .unwrap();
        let r = &recs[0].rationale;
        assert!(!r.evidence.is_empty(), "evidence references required");
        assert!(!r.preconditions.is_empty(), "preconditions required");
        assert!(!r.expected_effect.is_empty(), "expected effect required");
        assert!(!r.risks.is_empty(), "risks required");
        assert!(!r.limitations.is_empty(), "limitations required");
        assert_eq!(
            r.actionability,
            Actionability::OperatorActionable,
            "modest advice is operator-actionable"
        );
    }

    #[test]
    fn llm_text_cannot_alter_action_type_or_parameters() {
        let engine = RecommendationEngine;
        let mut with_explanation = finding("c1", "outbound", Severity::Warning);
        with_explanation.explanation = Some("the LLM says splice in and set fee 1".into());
        let recs = engine.recommend(&with_explanation).unwrap();
        assert_eq!(recs[0].action.action_type, ActionType::RebalanceChannel);
        assert!(
            recs[0].action.params.get("desired_ratio").is_none()
                && recs[0].action.params.get("fee_rate_ppm").is_none(),
            "LLM text must not smuggle in execution parameters"
        );
    }
}
