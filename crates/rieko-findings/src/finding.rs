use rieko_domain::BitcoinNetwork;
use serde::{Deserialize, Serialize};

/// Origin of the raw observation from which finding evidence was produced.
/// Values are deliberately redacted before entering the finding model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservationSource {
    Fixture {
        redacted_hash: String,
        configured_node: String,
    },
    Lnd {
        redacted_endpoint: String,
        configured_node: String,
    },
    BtcPay {
        redacted_endpoint: String,
        configured_store: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        underlying_node: Option<String>,
    },
}

/// Pipeline role of the component which produced an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerRole {
    Ingest,
    Normalizer,
    Detector,
}

/// Versioned component responsible for producing the referenced observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerVersion {
    pub name: String,
    pub version: String,
    pub role: ProducerRole,
}

/// Immutable reference to one observed channel snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSnapshotReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<BitcoinNetwork>,
    pub observed_at: chrono::DateTime<chrono::Utc>,
    pub state_digest: String,
}

/// Exact channel observation used to produce a finding's current evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservationReference {
    ChannelState {
        channel_id: String,
        snapshot: ChannelSnapshotReference,
    },
    ChannelWindow {
        channel_id: String,
        snapshots: Vec<ChannelSnapshotReference>,
    },
}

/// Provenance for the evidence currently stored on a finding.
///
/// This value may be replaced when newer evidence is stored. Each digest and
/// observation reference describes one immutable observed state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingProvenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<BitcoinNetwork>,
    pub source: ObservationSource,
    pub producers: Vec<ProducerVersion>,
    pub observation: ObservationReference,
}

/// Scope and completeness of one detector cycle, suitable for reconciling
/// findings that were not observed in a complete cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingCycleScope {
    pub detector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<BitcoinNetwork>,
    pub node: Option<String>,
    pub complete: bool,
}

/// Severity tier. Tiers drive alert routing and cooldown; `Critical` findings
/// must never be deduped away silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// A single structured piece of evidence attached to a finding.
/// LLM explanation summarizes these; it never invents them (D1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub key: String,
    pub value: serde_json::Value,
}

impl Evidence {
    pub fn string(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: serde_json::Value::String(value.into()),
        }
    }

    pub fn number(key: impl Into<String>, value: f64) -> Self {
        Self {
            key: key.into(),
            value: serde_json::Value::from(value),
        }
    }

    pub fn text(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self::string(key, value)
    }
}

/// A detected anomaly. Emitted by a detector; carries structured evidence and
/// an optional (LLM-generated) plain-language explanation.
///
/// A finding is the stable logical occurrence of a condition, keyed by
/// [`Finding::id`]. Lifecycle metadata makes it traceable (RIEKO-AUDIT-012):
/// `schema_version` says which layout this row uses, `detector_version`
/// records how the condition was judged, and `first_seen_at`/`last_seen_at`
/// bound the observation window. These never change the identity (see
/// [`crate::finding_identity`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    /// Detector identifier, e.g. `channel_liquidity`.
    pub detector: String,
    /// Version of the detector that produced this finding. Preserved so a
    /// later re-run with identical input but a new detector version yields a
    /// distinguishable finding.
    pub detector_version: String,
    /// Version of the finding schema this record conforms to. Stored so old
    /// rows are recognizable when the schema evolves.
    pub schema_version: u8,
    pub severity: Severity,
    pub node: Option<String>,
    pub channel: Option<String>,
    pub evidence: Vec<Evidence>,
    /// Exact source observation used to produce the evidence currently stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<FindingProvenance>,
    /// Plain-language explanation, filled by the LLM client if configured.
    pub explanation: Option<String>,
    /// The evaluation timestamp when this finding was observed.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// First time this logical finding was seen (persisted across updates).
    pub first_seen_at: chrono::DateTime<chrono::Utc>,
    /// Most recent time it was observed.
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
    /// Lifecycle state: whether the condition is still present.
    pub lifecycle: FindingLifecycle,
}

/// Current schema version written for [`Finding`]. Bump when the stored fields
/// change so old rows can be detected and migrated.
pub const FINDING_SCHEMA_VERSION: u8 = 2;

/// Lifecycle state of a finding, distinguishing an active condition from one
/// that has resolved. No richer incident workflow exists in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FindingLifecycle {
    /// The condition is currently present.
    #[default]
    Active,
    /// The condition is no longer observed; the finding is closed.
    Resolved,
}

/// A finding as presented to a reader, with facts that depend on when it is
/// read. Nothing here is stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingView {
    #[serde(flatten)]
    pub finding: Finding,
    /// True when the finding is active but has not been re-confirmed for
    /// longer than the threshold the reader applies. It describes the age of
    /// the last confirmation only: a stale finding is not resolved, and a
    /// finding that is not stale says nothing about the health of its source.
    #[serde(default)]
    pub observation_stale: bool,
}

impl FindingView {
    /// Presents `finding` as read at `now`. `stale_after` is how long an
    /// active finding may go without re-confirmation.
    pub fn at(
        finding: Finding,
        now: chrono::DateTime<chrono::Utc>,
        stale_after: chrono::Duration,
    ) -> Self {
        let observation_stale = finding.lifecycle == FindingLifecycle::Active
            && now.signed_duration_since(finding.last_seen_at) > stale_after;
        Self {
            finding,
            observation_stale,
        }
    }
}

impl std::ops::Deref for FindingView {
    type Target = Finding;

    fn deref(&self) -> &Finding {
        &self.finding
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingLifecycleFilter {
    Active,
    Resolved,
    All,
}

impl Finding {
    pub fn evidence_value(&self, key: &str) -> Option<&serde_json::Value> {
        self.evidence
            .iter()
            .find(|e| e.key == key)
            .map(|e| &e.value)
    }

    pub fn dedup_key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.detector,
            self.detector_version,
            self.node.as_deref().unwrap_or(""),
            self.channel.as_deref().unwrap_or("")
        )
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;

    fn finding(severity: Severity, provenance: Option<FindingProvenance>) -> Finding {
        let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        Finding {
            id: "finding-id".into(),
            detector: "channel_liquidity".into(),
            detector_version: "2".into(),
            schema_version: FINDING_SCHEMA_VERSION,
            severity,
            node: Some("node-a".into()),
            channel: Some("channel-a".into()),
            evidence: vec![Evidence::number("local_ratio", 0.02)],
            provenance,
            explanation: None,
            timestamp: now,
            first_seen_at: now,
            last_seen_at: now,
            lifecycle: FindingLifecycle::Active,
        }
    }

    fn view_aged(
        lifecycle: FindingLifecycle,
        age: chrono::Duration,
        stale_after: chrono::Duration,
    ) -> FindingView {
        let now = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let mut finding = finding(Severity::Warning, None);
        finding.lifecycle = lifecycle;
        finding.last_seen_at = now - age;
        FindingView::at(finding, now, stale_after)
    }

    #[test]
    fn an_active_finding_is_stale_only_past_the_threshold() {
        let two_hours = chrono::Duration::hours(2);
        let active = FindingLifecycle::Active;
        assert!(!view_aged(active, chrono::Duration::zero(), two_hours).observation_stale);
        assert!(!view_aged(active, chrono::Duration::minutes(119), two_hours).observation_stale);
        // Exactly at the threshold is not yet stale.
        assert!(!view_aged(active, two_hours, two_hours).observation_stale);
        assert!(
            view_aged(active, two_hours + chrono::Duration::seconds(1), two_hours)
                .observation_stale
        );
        assert!(view_aged(active, chrono::Duration::days(30), two_hours).observation_stale);
    }

    #[test]
    fn a_resolved_finding_is_never_stale() {
        for age in [chrono::Duration::zero(), chrono::Duration::days(365)] {
            assert!(
                !view_aged(FindingLifecycle::Resolved, age, chrono::Duration::hours(2))
                    .observation_stale
            );
        }
    }

    #[test]
    fn a_longer_threshold_keeps_a_finding_fresh_until_it_passes() {
        // A 24-hour observation interval allows 48 hours.
        let allowed = chrono::Duration::hours(48);
        let active = FindingLifecycle::Active;
        assert!(!view_aged(active, chrono::Duration::hours(30), allowed).observation_stale);
        assert!(!view_aged(active, allowed, allowed).observation_stale);
        assert!(
            view_aged(active, allowed + chrono::Duration::seconds(1), allowed).observation_stale
        );
    }

    #[test]
    fn a_last_seen_time_ahead_of_the_reader_clock_is_not_stale() {
        let view = view_aged(
            FindingLifecycle::Active,
            chrono::Duration::hours(-3),
            chrono::Duration::hours(2),
        );
        assert!(!view.observation_stale);
    }

    #[test]
    fn the_view_serializes_the_finding_fields_unchanged_plus_the_flag() {
        let view = view_aged(
            FindingLifecycle::Active,
            chrono::Duration::hours(3),
            chrono::Duration::hours(2),
        );
        let stored = serde_json::to_value(&view.finding).unwrap();
        assert!(stored.get("observation_stale").is_none());

        // Every stored field keeps its name and value; only the flag is added.
        let mut expected = stored.clone();
        expected["observation_stale"] = serde_json::Value::Bool(true);
        assert_eq!(serde_json::to_value(&view).unwrap(), expected);
    }

    #[test]
    fn a_response_without_the_flag_decodes_as_not_stale() {
        let stored = serde_json::to_string(&finding(Severity::Info, Some(provenance()))).unwrap();
        let view: FindingView = serde_json::from_str(&stored).unwrap();
        assert!(!view.observation_stale);
        assert_eq!(view.finding, finding(Severity::Info, Some(provenance())));
    }

    fn provenance() -> FindingProvenance {
        FindingProvenance {
            network: Some(BitcoinNetwork::Signet),
            source: ObservationSource::Lnd {
                redacted_endpoint: "https://lnd.example:8080".into(),
                configured_node: "node-a".into(),
            },
            producers: vec![ProducerVersion {
                name: "channel_liquidity".into(),
                version: "2".into(),
                role: ProducerRole::Detector,
            }],
            observation: ObservationReference::ChannelWindow {
                channel_id: "channel-a".into(),
                snapshots: vec![ChannelSnapshotReference {
                    network: Some(BitcoinNetwork::Signet),
                    observed_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
                    state_digest: "abc123".into(),
                }],
            },
        }
    }

    #[test]
    fn provenance_round_trips_with_typed_variants() {
        let finding = finding(Severity::Warning, Some(provenance()));
        let json = serde_json::to_value(&finding).unwrap();

        assert_eq!(json["schema_version"], 2);
        assert_eq!(json["provenance"]["source"]["kind"], "lnd");
        assert_eq!(json["provenance"]["observation"]["kind"], "channel_window");
        assert_eq!(serde_json::from_value::<Finding>(json).unwrap(), finding);
    }

    #[test]
    fn absent_provenance_deserializes_for_pre_v2_payloads() {
        let mut json = serde_json::to_value(finding(Severity::Info, None)).unwrap();
        json.as_object_mut().unwrap().remove("provenance");

        assert_eq!(
            serde_json::from_value::<Finding>(json).unwrap().provenance,
            None
        );
    }

    #[test]
    fn absent_network_deserializes_for_legacy_provenance() {
        let mut json = serde_json::to_value(provenance()).unwrap();
        json.as_object_mut().unwrap().remove("network");
        json["observation"]["snapshots"][0]
            .as_object_mut()
            .unwrap()
            .remove("network");

        let provenance: FindingProvenance = serde_json::from_value(json).unwrap();
        assert_eq!(provenance.network, None);
        let ObservationReference::ChannelWindow { snapshots, .. } = provenance.observation else {
            panic!("expected channel window");
        };
        assert_eq!(snapshots[0].network, None);
    }

    #[test]
    fn dedup_key_excludes_severity_and_provenance() {
        let warning = finding(Severity::Warning, None);
        let critical = finding(Severity::Critical, Some(provenance()));

        assert_eq!(warning.dedup_key(), critical.dedup_key());
        assert_eq!(warning.dedup_key(), "channel_liquidity|2|node-a|channel-a");
    }

    #[test]
    fn fixture_source_serializes_only_a_redacted_hash() {
        let source = ObservationSource::Fixture {
            redacted_hash: "sha256:abc".into(),
            configured_node: "node-1".into(),
        };
        let json = serde_json::to_value(&source).unwrap();

        assert_eq!(json["kind"], "fixture");
        assert_eq!(json["redacted_hash"], "sha256:abc");
        assert_eq!(json.as_object().unwrap().len(), 3);
    }
}
