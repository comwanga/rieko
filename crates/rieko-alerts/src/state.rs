use chrono::{DateTime, Utc};
use rieko_findings::Severity;
use serde::{Deserialize, Serialize};

/// Persisted alert-deduplication state for one dedup key. Keeping this in
/// durable storage means a monitor restart (or crash) cannot reset a cooldown
/// or the last-seen severity (D9, invariant #7). Timestamps are UTC so they
/// compare correctly across processes, never `Instant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertState {
    /// Last time this alert was actually delivered (successful send). `None`
    /// means never delivered. A failed send must not set this, so it cannot
    /// consume the cooldown.
    pub last_sent_at: Option<DateTime<Utc>>,
    /// Severity of the last delivered alert. Used to escalate immediately when
    /// the severity increases.
    pub last_severity: Option<Severity>,
    /// Outcome of the most recent attempt.
    pub last_status: DeliveryStatus,
}

impl AlertState {
    /// Default state: never delivered, nothing escalated, no status.
    pub fn never() -> Self {
        Self {
            last_sent_at: None,
            last_severity: None,
            last_status: DeliveryStatus::None,
        }
    }
}

/// What happened on the last delivery attempt for a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// Delivered to the sink.
    Success,
    /// Delivery attempted but failed; must not consume the cooldown.
    Failed,
    /// Suppressed because it was inside the cooldown window.
    Skipped,
    /// Never attempted.
    None,
}

/// Storage boundary for [`AlertState`], kept narrow so a cooldown/severity
/// survives across process restarts. Implemented by the durable backends.
pub trait AlertStateStore {
    fn read(&self, key: &str) -> Result<Option<AlertState>, crate::AlertError>;
    fn write(&mut self, key: &str, state: &AlertState) -> Result<(), crate::AlertError>;
}
