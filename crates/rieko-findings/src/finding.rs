use serde::{Deserialize, Serialize};

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
pub const FINDING_SCHEMA_VERSION: u8 = 1;

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

impl Finding {
    pub fn evidence_value(&self, key: &str) -> Option<&serde_json::Value> {
        self.evidence
            .iter()
            .find(|e| e.key == key)
            .map(|e| &e.value)
    }

    pub fn dedup_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.detector,
            self.detector_version,
            self.severity as i32,
            self.node.as_deref().unwrap_or(""),
            self.channel.as_deref().unwrap_or("")
        )
    }
}
