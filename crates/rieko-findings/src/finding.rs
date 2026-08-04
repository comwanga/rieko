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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    /// Detector identifier, e.g. `channel_liquidity`.
    pub detector: String,
    pub severity: Severity,
    pub node: Option<String>,
    pub channel: Option<String>,
    pub evidence: Vec<Evidence>,
    /// Plain-language explanation, filled by the LLM client if configured.
    pub explanation: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Finding {
    pub fn evidence_value(&self, key: &str) -> Option<&serde_json::Value> {
        self.evidence.iter().find(|e| e.key == key).map(|e| &e.value)
    }

    pub fn dedup_key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.detector,
            self.severity as i32,
            self.node.as_deref().unwrap_or(""),
            self.channel.as_deref().unwrap_or("")
        )
    }
}
