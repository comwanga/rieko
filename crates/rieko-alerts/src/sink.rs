use chrono::{DateTime, Utc};
use rieko_findings::Severity;
use thiserror::Error;

/// A human-facing alert derived from a finding. `dedup_key` identifies an
/// alert for cooldown purposes; it is derived from the finding's dedup key
/// plus severity so identical anomalies don't spam (D9).
#[derive(Debug, Clone)]
pub struct Alert {
    pub dedup_key: String,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

impl Alert {
    pub fn from_finding(
        finding: &rieko_findings::Finding,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            dedup_key: finding.dedup_key(),
            severity: finding.severity,
            title: title.into(),
            message: message.into(),
            timestamp: Utc::now(),
        }
    }
}

#[derive(Debug, Error)]
pub enum AlertError {
    #[error("alert sink failed: {0}")]
    Sink(String),
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
}

/// Where alerts go (Telegram, and later email/webhook/API).
pub trait AlertSink {
    fn send(&mut self, alert: &Alert) -> Result<(), AlertError>;
}
