use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The durable operational state Rieko persists so `/status` and the CLI
/// `status` command reflect real operation without scanning the whole database
/// (RIEKO-AUDIT-008). The record is constant size: one small row, queried
/// directly, never a million-row aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalState {
    /// Where channel data comes from.
    pub source: SourceState,
    /// Last time ingestion was attempted (fetching or loading the source).
    pub last_ingestion_attempt: Option<DateTime<Utc>>,
    /// Last ingestion that succeeded.
    pub last_ingestion_success: Option<DateTime<Utc>>,
    /// Last detector-cycle attempt.
    pub last_cycle_attempt: Option<DateTime<Utc>>,
    /// Last detector cycle that ran to completion (detection + persistence).
    pub last_cycle_success: Option<DateTime<Utc>>,
    /// Last successful persistence cycle (snapshots + findings + audit).
    pub last_persist_success: Option<DateTime<Utc>>,
    /// Newest source data timestamp observed, when available.
    pub source_data_at: Option<DateTime<Utc>>,
    /// LLM capability state, without any secrets.
    pub llm: ComponentState,
    /// Alert sink capability state, without any secrets.
    pub alert_sink: ComponentState,
    /// Retention cleanup state: Healthy after a successful pass, Failing when
    /// the last pass errored, NotConfigured before any pass (RIEKO-AUDIT-016).
    pub cleanup: ComponentState,
    /// Last time a retention cleanup was attempted.
    pub last_cleanup_attempt: Option<DateTime<Utc>>,
    /// Last retention cleanup that completed successfully.
    pub last_cleanup_success: Option<DateTime<Utc>>,
}

impl Default for OperationalState {
    fn default() -> Self {
        Self {
            source: SourceState::default(),
            last_ingestion_attempt: None,
            last_ingestion_success: None,
            last_cycle_attempt: None,
            last_cycle_success: None,
            last_persist_success: None,
            source_data_at: None,
            llm: ComponentState::NotConfigured,
            alert_sink: ComponentState::NotConfigured,
            cleanup: ComponentState::NotConfigured,
            last_cleanup_attempt: None,
            last_cleanup_success: None,
        }
    }
}

/// What kind of source feeds the pipeline and whether it is reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SourceState {
    /// A JSON fixture. Connectivity is inherently fine once loaded.
    #[default]
    Fixture,
    /// A live LND REST node.
    LndRest { connected: bool },
    /// A live BTCPay Server Greenfield API.
    BtcPayGreenfield { connected: bool },
}

impl SourceState {
    /// Whether ingestion from this source can currently reach its data.
    pub fn connected(&self) -> bool {
        match self {
            SourceState::Fixture => true,
            SourceState::LndRest { connected } => *connected,
            SourceState::BtcPayGreenfield { connected } => *connected,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SourceState::Fixture => "fixture",
            SourceState::LndRest { .. } => "lnd_rest",
            SourceState::BtcPayGreenfield { .. } => "btcpay_greenfield",
        }
    }
}

/// Capability state of an optional component (LLM, alert sink).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentState {
    /// Not configured; absence is expected and not a problem.
    NotConfigured,
    /// Configured, but not yet verified by a successful operation.
    Configured,
    /// Configured and functioning.
    Healthy,
    /// Configured but failing.
    Failing,
}

impl ComponentState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Configured => "configured",
            Self::Healthy => "healthy",
            Self::Failing => "failing",
        }
    }
}

/// Overall operational state (RIEKO-AUDIT-008). Exact rules are documented in
/// [`crate::assess`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverallState {
    /// Rieko has never completed an ingestion.
    NotInitialized,
    /// Operating within policy.
    Healthy,
    /// Operating but degraded (stale data, a configured component failing).
    Degraded,
    /// Not operating correctly (database corruption, no source data ever).
    Unhealthy,
}

impl OverallState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "not_initialized",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }
}
