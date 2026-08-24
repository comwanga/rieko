use rieko_findings::{
    Action, ActionType, Actionability, Finding, FindingLifecycle, Rationale, Recommendation,
    Severity, FINDING_SCHEMA_VERSION,
};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecommendationEngineError {
    #[error("cannot recommend for finding {finding_id}: unsupported detector {detector}")]
    UnsupportedDetector {
        finding_id: String,
        detector: String,
    },
    #[error(
        "cannot recommend for finding {finding_id}: unsupported {detector} detector version {version}"
    )]
    UnsupportedDetectorVersion {
        finding_id: String,
        detector: String,
        version: String,
    },
    #[error(
        "cannot recommend for finding {finding_id}: unsupported finding schema version {version} (current {current})"
    )]
    UnsupportedSchemaVersion {
        finding_id: String,
        version: u8,
        current: u8,
    },
    #[error("cannot recommend for finding {finding_id}: finding is not active")]
    InactiveFinding { finding_id: String },
    #[error("cannot recommend for finding {finding_id}: unsupported severity {severity:?}")]
    UnsupportedSeverity {
        finding_id: String,
        severity: Severity,
    },
    #[error("cannot recommend for finding {finding_id}: no target channel")]
    MissingChannel { finding_id: String },
    #[error("cannot recommend for finding {finding_id}: target channel is empty")]
    EmptyChannel { finding_id: String },
    #[error("cannot recommend for finding {finding_id}: evidence key at index {index} is empty")]
    EmptyEvidenceKey { finding_id: String, index: usize },
    #[error("cannot recommend for finding {finding_id}: duplicate evidence key {key}")]
    DuplicateEvidenceKey { finding_id: String, key: String },
    #[error("cannot recommend for finding {finding_id}: missing evidence {key}")]
    MissingEvidence {
        finding_id: String,
        key: &'static str,
    },
    #[error("cannot recommend for finding {finding_id}: evidence {key} must be {expected}")]
    InvalidEvidence {
        finding_id: String,
        key: &'static str,
        expected: &'static str,
    },
    #[error("cannot recommend for finding {finding_id}: unknown direction {direction}")]
    UnknownDirection {
        finding_id: String,
        direction: String,
    },
}

#[derive(Debug, Clone, Copy)]
enum LiquidityDirection {
    Outbound,
    Inbound,
}

struct ChannelLiquidityInput {
    channel: String,
    direction: LiquidityDirection,
    evidence_refs: Vec<String>,
}

struct LiquidityTrendInput {
    channel: String,
    start_ratio: f64,
    current_ratio: f64,
    decline: f64,
    window: u64,
    evidence_refs: Vec<String>,
}

struct SettlementReliabilityInput {
    channel: Option<String>,
    expired_invoices: f64,
    settled_invoices: f64,
    failure_rate: f64,
    chain_synchronized: bool,
    root_cause: String,
    evidence_refs: Vec<String>,
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
            "channel_liquidity" => {
                let input = ChannelLiquidityInput::parse(finding)?;
                Ok(self.recommend_liquidity(finding, input))
            }
            "liquidity_trend" => {
                let input = LiquidityTrendInput::parse(finding)?;
                Ok(self.recommend_liquidity_trend(finding, input))
            }
            "settlement_reliability" => {
                let input = SettlementReliabilityInput::parse(finding)?;
                Ok(self.recommend_settlement_reliability(finding, input))
            }
            detector => Err(RecommendationEngineError::UnsupportedDetector {
                finding_id: finding.id.clone(),
                detector: detector.to_string(),
            }),
        }
    }

    fn recommend_liquidity(
        &self,
        finding: &Finding,
        input: ChannelLiquidityInput,
    ) -> Vec<Recommendation> {
        match input.direction {
            LiquidityDirection::Outbound => vec![build_rebased_review(
                finding,
                input.channel,
                "outbound",
                &input.evidence_refs,
            )],
            LiquidityDirection::Inbound => vec![
                build_fee_review(finding, &input.channel, "inbound", &input.evidence_refs),
                build_rebased_review(finding, input.channel, "inbound", &input.evidence_refs),
            ],
        }
    }

    fn recommend_liquidity_trend(
        &self,
        finding: &Finding,
        input: LiquidityTrendInput,
    ) -> Vec<Recommendation> {
        let LiquidityTrendInput {
            channel,
            start_ratio,
            current_ratio,
            decline,
            window,
            evidence_refs,
        } = input;

        vec![Recommendation {
            finding_id: finding.id.clone(),
            action: Action::for_recommendation(
                &finding.id,
                ActionType::RebalanceChannel,
                Some(channel.clone()),
                serde_json::json!({
                    "reason": "channel liquidity is trending down",
                    "decline": decline,
                    "start_ratio": start_ratio,
                    "current_ratio": current_ratio,
                    "window": window,
                }),
                format!(
                    "Channel {channel} is trending toward outbound drain: local ratio declined \
                     from {:.4} to {:.4} over the last {} snapshots. \
                     Inspect recent forwarding activity to confirm whether the trend \
                     is expected.",
                    start_ratio, current_ratio, window,
                ),
            ),
            rationale: Rationale {
                evidence: evidence_refs,
                preconditions: vec![
                    format!(
                        "Confirm channel {channel} is meant to route outbound; if it is a \
                         pure sink (revenue) channel the decline is expected."
                    ),
                    "Confirm the decline is not caused by a single large payment.".into(),
                    "Validate the trend by comparing with forwarding history.".into(),
                ],
                expected_effect: "If the decline is unexpected, investigating routing demand and \
                                  peer behaviour can help decide whether rebalancing is needed."
                    .into(),
                risks: vec![
                    "Any decline in a revenue channel is normal — do not rebalance without \
                     confirming the channel's role."
                        .into(),
                    "Rebalancing costs may exceed the benefit if the decline is temporary.".into(),
                ],
                limitations: vec![
                    "The trend is based on snapshot ratios alone, not forwarding volume.".into(),
                    format!(
                        "The window covers only the last {} snapshots; longer-term trends \
                             may look different.",
                        window
                    ),
                ],
                actionability: Actionability::OperatorActionable,
            },
            lifecycle: None,
        }]
    }

    fn recommend_settlement_reliability(
        &self,
        finding: &Finding,
        input: SettlementReliabilityInput,
    ) -> Vec<Recommendation> {
        let SettlementReliabilityInput {
            channel,
            expired_invoices,
            settled_invoices,
            failure_rate,
            chain_synchronized,
            root_cause,
            evidence_refs,
        } = input;

        let target_chan = channel.unwrap_or_else(|| "primary-routing-path".to_string());

        let summary = if chain_synchronized {
            format!(
                "Lightning invoice settlement degradation detected: {:.1}% failure rate ({} expired, {} settled). \
                 Bitcoin Core node is synchronized; rebalance channel {} to restore outbound liquidity on merchant settlement paths.",
                failure_rate * 100.0,
                expired_invoices as u64,
                settled_invoices as u64,
                target_chan
            )
        } else {
            format!(
                "Invoice settlement failure rate is elevated ({:.1}% failure rate). \
                 Bitcoin Core is not synchronized; verify chain synchronization before executing Lightning rebalances.",
                failure_rate * 100.0
            )
        };

        vec![Recommendation {
            finding_id: finding.id.clone(),
            action: Action::for_recommendation(
                &finding.id,
                ActionType::RebalanceChannel,
                Some(target_chan.clone()),
                serde_json::json!({
                    "reason": "lightning invoice settlement reliability degradation",
                    "failure_rate": failure_rate,
                    "expired_invoices": expired_invoices,
                    "settled_invoices": settled_invoices,
                    "chain_synchronized": chain_synchronized,
                    "root_cause": root_cause,
                    "target_channel": target_chan,
                }),
                summary,
            ),
            rationale: Rationale {
                evidence: evidence_refs,
                preconditions: vec![
                    format!("Inspect channel {target_chan} local and remote balance split."),
                    "Verify node on-chain and off-chain liquidity reserves.".into(),
                    "Confirm Bitcoin Core RPC connection remains responsive.".into(),
                ],
                expected_effect: "Restores local outbound liquidity on settlement channels, reducing invoice expiry failures.".into(),
                risks: vec![
                    "Circular rebalance consumes routing fees on intermediate hops.".into(),
                    "Opening or resizing channels during mempool congestion increases on-chain fee cost.".into(),
                ],
                limitations: vec![
                    "Metric aggregates failures across recent webhook/event window.".into(),
                    "Individual payment failures may also be caused by destination invoice expiry or path unreachability.".into(),
                ],
                actionability: Actionability::OperatorActionable,
            },
            lifecycle: None,
        }]
    }
}

impl ChannelLiquidityInput {
    fn parse(finding: &Finding) -> Result<Self, RecommendationEngineError> {
        let version = validate_common(finding)?;
        let channel = channel(finding)?;
        let direction = match required_text(finding, "direction")? {
            "outbound" => LiquidityDirection::Outbound,
            "inbound" => LiquidityDirection::Inbound,
            direction => {
                return Err(RecommendationEngineError::UnknownDirection {
                    finding_id: finding.id.clone(),
                    direction: direction.to_string(),
                })
            }
        };

        required_ratio(finding, "local_ratio")?;
        required_nonnegative_number(finding, "local_balance_msat")?;
        required_nonnegative_number(finding, "remote_balance_msat")?;
        required_positive_number(finding, "capacity_msat")?;
        required_nonempty_text(finding, "peer")?;
        if version == 2 {
            required_ratio(finding, "severity_threshold")?;
        }

        Ok(Self {
            channel,
            direction,
            evidence_refs: evidence_refs(finding),
        })
    }
}

impl LiquidityTrendInput {
    fn parse(finding: &Finding) -> Result<Self, RecommendationEngineError> {
        validate_common(finding)?;
        let channel = channel(finding)?;
        let direction = required_text(finding, "direction")?;
        if direction != "draining" {
            return Err(RecommendationEngineError::UnknownDirection {
                finding_id: finding.id.clone(),
                direction: direction.to_string(),
            });
        }

        let start_ratio = required_ratio(finding, "start_ratio")?;
        let current_ratio = required_ratio(finding, "current_ratio")?;
        let decline = required_ratio(finding, "decline")?;
        required_ratio(finding, "min_in_window")?;
        required_nonempty_text(finding, "peer")?;
        let raw_window = required_number(finding, "window", "a positive integral number")?;
        if raw_window <= 0.0 || raw_window.fract() != 0.0 || raw_window >= u64::MAX as f64 {
            return Err(invalid_evidence(
                finding,
                "window",
                "a positive integral number",
            ));
        }

        Ok(Self {
            channel,
            start_ratio,
            current_ratio,
            decline,
            window: raw_window as u64,
            evidence_refs: evidence_refs(finding),
        })
    }
}

impl SettlementReliabilityInput {
    fn parse(finding: &Finding) -> Result<Self, RecommendationEngineError> {
        validate_common(finding)?;
        let expired_invoices = required_nonnegative_number(finding, "expired_invoices")?;
        let settled_invoices = required_nonnegative_number(finding, "settled_invoices")?;
        let failure_rate = required_ratio(finding, "failure_rate")?;
        let chain_sync_str = required_nonempty_text(finding, "chain_synchronized")?;
        let chain_synchronized = chain_sync_str == "true";
        let root_cause = required_nonempty_text(finding, "root_cause")?.to_string();

        let channel = finding.channel.clone().filter(|c| !c.trim().is_empty());

        Ok(Self {
            channel,
            expired_invoices,
            settled_invoices,
            failure_rate,
            chain_synchronized,
            root_cause,
            evidence_refs: evidence_refs(finding),
        })
    }
}

fn validate_common(finding: &Finding) -> Result<u8, RecommendationEngineError> {
    let version = match finding.detector_version.as_str() {
        "1" => 1,
        "2" => 2,
        _ => {
            return Err(RecommendationEngineError::UnsupportedDetectorVersion {
                finding_id: finding.id.clone(),
                detector: finding.detector.clone(),
                version: finding.detector_version.clone(),
            })
        }
    };
    if !(1..=FINDING_SCHEMA_VERSION).contains(&finding.schema_version) {
        return Err(RecommendationEngineError::UnsupportedSchemaVersion {
            finding_id: finding.id.clone(),
            version: finding.schema_version,
            current: FINDING_SCHEMA_VERSION,
        });
    }
    if finding.lifecycle != FindingLifecycle::Active {
        return Err(RecommendationEngineError::InactiveFinding {
            finding_id: finding.id.clone(),
        });
    }
    if !matches!(finding.severity, Severity::Warning | Severity::Critical) {
        return Err(RecommendationEngineError::UnsupportedSeverity {
            finding_id: finding.id.clone(),
            severity: finding.severity,
        });
    }

    let mut keys = HashSet::with_capacity(finding.evidence.len());
    for (index, evidence) in finding.evidence.iter().enumerate() {
        if evidence.key.trim().is_empty() {
            return Err(RecommendationEngineError::EmptyEvidenceKey {
                finding_id: finding.id.clone(),
                index,
            });
        }
        if !keys.insert(evidence.key.as_str()) {
            return Err(RecommendationEngineError::DuplicateEvidenceKey {
                finding_id: finding.id.clone(),
                key: evidence.key.clone(),
            });
        }
    }
    Ok(version)
}

fn channel(finding: &Finding) -> Result<String, RecommendationEngineError> {
    let channel =
        finding
            .channel
            .as_ref()
            .ok_or_else(|| RecommendationEngineError::MissingChannel {
                finding_id: finding.id.clone(),
            })?;
    if channel.trim().is_empty() {
        return Err(RecommendationEngineError::EmptyChannel {
            finding_id: finding.id.clone(),
        });
    }
    Ok(channel.clone())
}

fn required_value<'a>(
    finding: &'a Finding,
    key: &'static str,
) -> Result<&'a serde_json::Value, RecommendationEngineError> {
    finding
        .evidence_value(key)
        .ok_or_else(|| RecommendationEngineError::MissingEvidence {
            finding_id: finding.id.clone(),
            key,
        })
}

fn required_text<'a>(
    finding: &'a Finding,
    key: &'static str,
) -> Result<&'a str, RecommendationEngineError> {
    required_value(finding, key)?
        .as_str()
        .ok_or_else(|| invalid_evidence(finding, key, "a string"))
}

fn required_nonempty_text<'a>(
    finding: &'a Finding,
    key: &'static str,
) -> Result<&'a str, RecommendationEngineError> {
    let value = required_text(finding, key)?;
    if value.trim().is_empty() {
        return Err(invalid_evidence(finding, key, "a non-empty string"));
    }
    Ok(value)
}

fn required_number(
    finding: &Finding,
    key: &'static str,
    expected: &'static str,
) -> Result<f64, RecommendationEngineError> {
    let value = required_value(finding, key)?
        .as_f64()
        .ok_or_else(|| invalid_evidence(finding, key, expected))?;
    if !value.is_finite() {
        return Err(invalid_evidence(finding, key, expected));
    }
    Ok(value)
}

fn required_ratio(finding: &Finding, key: &'static str) -> Result<f64, RecommendationEngineError> {
    let value = required_number(finding, key, "a finite number in 0..=1")?;
    if !(0.0..=1.0).contains(&value) {
        return Err(invalid_evidence(finding, key, "a finite number in 0..=1"));
    }
    Ok(value)
}

fn required_nonnegative_number(
    finding: &Finding,
    key: &'static str,
) -> Result<f64, RecommendationEngineError> {
    let value = required_number(finding, key, "a finite non-negative number")?;
    if value < 0.0 {
        return Err(invalid_evidence(
            finding,
            key,
            "a finite non-negative number",
        ));
    }
    Ok(value)
}

fn required_positive_number(
    finding: &Finding,
    key: &'static str,
) -> Result<f64, RecommendationEngineError> {
    let value = required_number(finding, key, "a finite positive number")?;
    if value <= 0.0 {
        return Err(invalid_evidence(finding, key, "a finite positive number"));
    }
    Ok(value)
}

fn invalid_evidence(
    finding: &Finding,
    key: &'static str,
    expected: &'static str,
) -> RecommendationEngineError {
    RecommendationEngineError::InvalidEvidence {
        finding_id: finding.id.clone(),
        key,
        expected,
    }
}

fn evidence_refs(finding: &Finding) -> Vec<String> {
    finding
        .evidence
        .iter()
        .map(|e| format!("{}={}", e.key, e.value))
        .collect()
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
            expected_effect: "If rebalancing is warranted, restoring capacity on the drained side could let the channel route payments in that direction again."
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
        lifecycle: None,
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
        lifecycle: None,
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
                Evidence::number("local_balance_msat", 100_000.0),
                Evidence::number("remote_balance_msat", 900_000.0),
                Evidence::number("capacity_msat", 1_000_000.0),
                Evidence::text("peer", "peer-1"),
            ],
            provenance: None,
            explanation: None,
            timestamp: now,
            first_seen_at: now,
            last_seen_at: now,
            lifecycle: rieko_findings::FindingLifecycle::Active,
        }
    }

    fn trend_finding() -> Finding {
        let now = chrono::Utc::now();
        Finding {
            id: "f2".into(),
            detector: "liquidity_trend".into(),
            detector_version: "2".into(),
            schema_version: rieko_findings::FINDING_SCHEMA_VERSION,
            severity: Severity::Warning,
            node: Some("local-node".into()),
            channel: Some("c2".into()),
            evidence: vec![
                Evidence::text("direction", "draining"),
                Evidence::number("start_ratio", 0.35),
                Evidence::number("current_ratio", 0.24),
                Evidence::number("decline", 0.11),
                Evidence::number("min_in_window", 0.24),
                Evidence::number("window", 12.0),
                Evidence::text("peer", "peer-1"),
            ],
            provenance: None,
            explanation: None,
            timestamp: now,
            first_seen_at: now,
            last_seen_at: now,
            lifecycle: rieko_findings::FindingLifecycle::Active,
        }
    }

    fn set_evidence(finding: &mut Finding, key: &str, value: serde_json::Value) {
        finding
            .evidence
            .iter_mut()
            .find(|e| e.key == key)
            .unwrap()
            .value = value;
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
        assert!(matches!(
            engine.recommend(&f),
            Err(RecommendationEngineError::UnsupportedDetector { detector, .. })
                if detector == "magic"
        ));
    }

    #[test]
    fn all_supported_typed_paths_produce_actions() {
        let engine = RecommendationEngine;
        for version in ["1", "2"] {
            for direction in ["outbound", "inbound"] {
                for severity in [Severity::Warning, Severity::Critical] {
                    let mut f = finding("c1", direction, severity);
                    f.detector_version = version.into();
                    if version == "2" {
                        f.evidence
                            .push(Evidence::number("severity_threshold", 0.05));
                    }
                    assert!(!engine.recommend(&f).unwrap().is_empty());
                }
            }

            for severity in [Severity::Warning, Severity::Critical] {
                let mut f = trend_finding();
                f.detector_version = version.into();
                f.severity = severity;
                assert!(!engine.recommend(&f).unwrap().is_empty());
            }
        }
    }

    #[test]
    fn v1_liquidity_evidence_remains_compatible() {
        let f = finding("c1", "outbound", Severity::Warning);
        assert_eq!(f.detector_version, "1");
        assert!(f.evidence_value("severity_threshold").is_none());
        assert_eq!(RecommendationEngine.recommend(&f).unwrap().len(), 1);
    }

    #[test]
    fn v2_liquidity_requires_its_added_evidence() {
        let mut f = finding("c1", "outbound", Severity::Warning);
        f.detector_version = "2".into();
        assert!(matches!(
            RecommendationEngine.recommend(&f),
            Err(RecommendationEngineError::MissingEvidence {
                key: "severity_threshold",
                ..
            })
        ));
        f.evidence
            .push(Evidence::number("severity_threshold", 0.05));
        assert!(!RecommendationEngine.recommend(&f).unwrap().is_empty());
    }

    #[test]
    fn unsupported_versions_and_ineligible_findings_are_rejected() {
        let engine = RecommendationEngine;
        let base = finding("c1", "outbound", Severity::Warning);

        let mut f = base.clone();
        f.detector_version = "3".into();
        assert!(matches!(
            engine.recommend(&f),
            Err(RecommendationEngineError::UnsupportedDetectorVersion { .. })
        ));

        for schema_version in [0, rieko_findings::FINDING_SCHEMA_VERSION + 1] {
            let mut f = base.clone();
            f.schema_version = schema_version;
            assert!(matches!(
                engine.recommend(&f),
                Err(RecommendationEngineError::UnsupportedSchemaVersion { .. })
            ));
        }

        let mut f = base.clone();
        f.lifecycle = rieko_findings::FindingLifecycle::Resolved;
        assert!(matches!(
            engine.recommend(&f),
            Err(RecommendationEngineError::InactiveFinding { .. })
        ));

        let mut f = base;
        f.severity = Severity::Info;
        assert!(matches!(
            engine.recommend(&f),
            Err(RecommendationEngineError::UnsupportedSeverity { .. })
        ));
    }

    #[test]
    fn missing_or_empty_channel_is_rejected() {
        let engine = RecommendationEngine;
        let mut f = finding("c1", "outbound", Severity::Warning);
        f.channel = None;
        assert!(matches!(
            engine.recommend(&f),
            Err(RecommendationEngineError::MissingChannel { .. })
        ));

        f.channel = Some("  ".into());
        assert!(matches!(
            engine.recommend(&f),
            Err(RecommendationEngineError::EmptyChannel { .. })
        ));
    }

    #[test]
    fn evidence_keys_must_be_nonempty_and_unique() {
        let engine = RecommendationEngine;
        let mut f = finding("c1", "outbound", Severity::Warning);
        f.evidence.push(Evidence::text(" ", "value"));
        assert!(matches!(
            engine.recommend(&f),
            Err(RecommendationEngineError::EmptyEvidenceKey { .. })
        ));

        let mut f = finding("c1", "outbound", Severity::Warning);
        f.evidence.push(Evidence::text("direction", "inbound"));
        assert!(matches!(
            engine.recommend(&f),
            Err(RecommendationEngineError::DuplicateEvidenceKey { key, .. })
                if key == "direction"
        ));
    }

    #[test]
    fn liquidity_required_evidence_is_fail_closed() {
        let required = [
            "direction",
            "local_ratio",
            "local_balance_msat",
            "remote_balance_msat",
            "capacity_msat",
            "peer",
        ];
        for key in required {
            let mut f = finding("c1", "outbound", Severity::Warning);
            f.evidence.retain(|e| e.key != key);
            assert!(matches!(
                RecommendationEngine.recommend(&f),
                Err(RecommendationEngineError::MissingEvidence { key: missing, .. })
                    if missing == key
            ));
        }

        let mut f = finding("c1", "outbound", Severity::Warning);
        set_evidence(&mut f, "local_ratio", serde_json::json!(1.01));
        assert!(matches!(
            RecommendationEngine.recommend(&f),
            Err(RecommendationEngineError::InvalidEvidence {
                key: "local_ratio",
                ..
            })
        ));

        let mut f = finding("c1", "outbound", Severity::Warning);
        set_evidence(&mut f, "capacity_msat", serde_json::json!(0));
        assert!(matches!(
            RecommendationEngine.recommend(&f),
            Err(RecommendationEngineError::InvalidEvidence {
                key: "capacity_msat",
                ..
            })
        ));

        let f = finding("c1", "sideways", Severity::Warning);
        assert!(matches!(
            RecommendationEngine.recommend(&f),
            Err(RecommendationEngineError::UnknownDirection { .. })
        ));
    }

    #[test]
    fn trend_required_evidence_and_window_are_fail_closed() {
        let required = [
            "direction",
            "start_ratio",
            "current_ratio",
            "decline",
            "min_in_window",
            "window",
            "peer",
        ];
        for key in required {
            let mut f = trend_finding();
            f.evidence.retain(|e| e.key != key);
            assert!(matches!(
                RecommendationEngine.recommend(&f),
                Err(RecommendationEngineError::MissingEvidence { key: missing, .. })
                    if missing == key
            ));
        }

        for invalid in [
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!(1.5),
        ] {
            let mut f = trend_finding();
            set_evidence(&mut f, "window", invalid);
            assert!(matches!(
                RecommendationEngine.recommend(&f),
                Err(RecommendationEngineError::InvalidEvidence { key: "window", .. })
            ));
        }

        let mut f = trend_finding();
        set_evidence(&mut f, "direction", serde_json::json!("growing"));
        assert!(matches!(
            RecommendationEngine.recommend(&f),
            Err(RecommendationEngineError::UnknownDirection { .. })
        ));

        let mut f = trend_finding();
        set_evidence(&mut f, "decline", serde_json::json!("0.11"));
        assert!(matches!(
            RecommendationEngine.recommend(&f),
            Err(RecommendationEngineError::InvalidEvidence { key: "decline", .. })
        ));
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
        let mut all_recommendations = Vec::new();
        for direction in ["outbound", "inbound"] {
            for severity in [Severity::Warning, Severity::Critical] {
                all_recommendations.extend(
                    engine
                        .recommend(&finding("c1", direction, severity))
                        .unwrap(),
                );
            }
        }
        all_recommendations.extend(engine.recommend(&trend_finding()).unwrap());

        for rec in all_recommendations {
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

    #[test]
    fn drift_trend_produces_modest_investigation_recommendation() {
        let finding = trend_finding();
        let engine = RecommendationEngine;
        let recs = engine.recommend(&finding).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].action.action_type, ActionType::RebalanceChannel);
        assert_eq!(recs[0].action.stage, ActionStage::Recommended);
        assert_eq!(recs[0].action.target.as_deref(), Some("c2"));
        let summary = &recs[0].action.summary;
        assert!(summary.contains("c2"), "summary must mention channel");
        assert!(summary.contains("0.35"), "summary must include start ratio");
        assert!(
            summary.contains("0.24"),
            "summary must include current ratio"
        );
    }

    #[test]
    fn settlement_reliability_produces_rebalance_recommendation() {
        let now = chrono::Utc::now();
        let finding = Finding {
            id: "settlement-finding-1".into(),
            detector: "settlement_reliability".into(),
            detector_version: "1".into(),
            schema_version: FINDING_SCHEMA_VERSION,
            severity: Severity::Critical,
            node: Some("node-test".into()),
            channel: Some("chan-bottleneck".into()),
            evidence: vec![
                Evidence::number("expired_invoices", 4.0),
                Evidence::number("settled_invoices", 1.0),
                Evidence::number("total_invoices", 5.0),
                Evidence::number("failure_rate", 0.80),
                Evidence::number("drained_channels_count", 1.0),
                Evidence::number("inactive_channels_count", 0.0),
                Evidence::string("chain_synchronized", "true"),
                Evidence::string("diagnosis", "lightning_settlement_degraded"),
                Evidence::string("root_cause", "lightning_operational_degradation"),
            ],
            provenance: None,
            explanation: Some("Degraded settlement reliability".into()),
            timestamp: now,
            first_seen_at: now,
            last_seen_at: now,
            lifecycle: FindingLifecycle::Active,
        };

        let engine = RecommendationEngine;
        let recs = engine.recommend(&finding).unwrap();
        assert_eq!(recs.len(), 1);
        let rec = &recs[0];
        assert_eq!(rec.action.action_type, ActionType::RebalanceChannel);
        assert_eq!(rec.action.stage, ActionStage::Recommended);
        assert_eq!(rec.action.target.as_deref(), Some("chan-bottleneck"));
        assert!(rec.action.summary.contains("chan-bottleneck"));
        assert!(rec.action.summary.contains("80.0% failure rate"));
        assert_eq!(
            rec.rationale.actionability,
            Actionability::OperatorActionable
        );
    }
}
