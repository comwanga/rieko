use chrono::{DateTime, Duration, Utc};

use crate::state::{ComponentState, OperationalState, OverallState, SourceState};

/// Policy knobs that turn raw operational state into an overall verdict.
#[derive(Debug, Clone)]
pub struct HealthPolicy {
    /// How old source data may be before the pipeline is stale.
    pub freshness: Duration,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            freshness: Duration::hours(2),
        }
    }
}

/// Exact health semantics (RIEKO-AUDIT-008).
///
/// * **NotInitialized**: no ingestion has ever succeeded.
/// * **Unhealthy**: the database failed its integrity check, or a live source
///   was configured but has never connected.
/// * **Degraded**:
///   * the latest ingestion attempt failed while valid older data exists;
///   * source data is older than the freshness threshold;
///   * an LLM is configured but failing (explanations expected);
///   * an alert sink is configured but failing.
/// * **Healthy**: a recent ingestion succeeded, data is fresh, and every
///   configured component is working.
///
/// A zero-data database is never called healthy: with no successful ingestion
/// it is `NotInitialized`, not `Healthy`.
///
/// `db_integrity_ok` is computed by the caller (SQLite `quick_check`); a false
/// value forces `Unhealthy` regardless of everything else.
pub fn assess(
    state: &OperationalState,
    policy: &HealthPolicy,
    now: DateTime<Utc>,
    db_integrity_ok: bool,
) -> OverallState {
    if !db_integrity_ok {
        return OverallState::Unhealthy;
    }

    let Some(last_success) = state.last_ingestion_success else {
        // Never ingested anything. A configured live source that has also
        // never connected is not operating at all, rather than not-yet-used.
        if matches!(state.source, SourceState::LndRest { connected: false }) {
            return OverallState::Unhealthy;
        }
        return OverallState::NotInitialized;
    };

    let mut degraded = false;

    // Latest attempt failed but recent valid data exists.
    if let Some(attempt) = state.last_ingestion_attempt {
        if attempt > last_success {
            degraded = true;
        }
    }

    // Data older than the freshness threshold.
    if let Some(data_at) = state.source_data_at {
        if now - data_at > policy.freshness {
            degraded = true;
        }
    }

    // A configured component that is failing.
    if state.llm == ComponentState::Failing || state.alert_sink == ComponentState::Failing {
        degraded = true;
    }

    if degraded {
        OverallState::Degraded
    } else {
        OverallState::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SourceState;

    fn base() -> OperationalState {
        OperationalState::default()
    }

    #[test]
    fn empty_fresh_db_is_not_initialized_not_healthy() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        // No ingestion ever: NotInitialized, and never Healthy.
        assert_eq!(
            assess(&base(), &policy, now, true),
            OverallState::NotInitialized
        );
        assert_ne!(assess(&base(), &policy, now, true), OverallState::Healthy);
    }

    #[test]
    fn healthy_after_successful_recent_ingestion() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.source = SourceState::Fixture;
        s.last_ingestion_attempt = Some(now - Duration::seconds(10));
        s.last_ingestion_success = Some(now - Duration::seconds(10));
        s.source_data_at = Some(now - Duration::seconds(5));
        assert_eq!(assess(&s, &policy, now, true), OverallState::Healthy);
    }

    #[test]
    fn stale_data_is_degraded() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.last_ingestion_success = Some(now - Duration::seconds(10));
        s.source_data_at = Some(now - Duration::hours(10));
        assert_eq!(assess(&s, &policy, now, true), OverallState::Degraded);
    }

    #[test]
    fn latest_ingestion_failed_but_recent_data_is_degraded() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.last_ingestion_success = Some(now - Duration::seconds(60));
        s.last_ingestion_attempt = Some(now - Duration::seconds(5));
        s.source_data_at = Some(now - Duration::seconds(5));
        assert_eq!(assess(&s, &policy, now, true), OverallState::Degraded);
    }

    #[test]
    fn database_failure_is_unhealthy() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.last_ingestion_success = Some(now - Duration::seconds(10));
        assert_eq!(assess(&s, &policy, now, false), OverallState::Unhealthy);
    }

    #[test]
    fn llm_absent_by_choice_is_not_degraded() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.last_ingestion_success = Some(now - Duration::seconds(10));
        s.source_data_at = Some(now - Duration::seconds(5));
        s.llm = ComponentState::NotConfigured;
        assert_eq!(assess(&s, &policy, now, true), OverallState::Healthy);
    }

    #[test]
    fn configured_llm_failing_is_degraded() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.last_ingestion_success = Some(now - Duration::seconds(10));
        s.source_data_at = Some(now - Duration::seconds(5));
        s.llm = ComponentState::Failing;
        assert_eq!(assess(&s, &policy, now, true), OverallState::Degraded);
    }

    #[test]
    fn telegram_configured_and_failing_is_degraded() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.last_ingestion_success = Some(now - Duration::seconds(10));
        s.source_data_at = Some(now - Duration::seconds(5));
        s.alert_sink = ComponentState::Failing;
        assert_eq!(assess(&s, &policy, now, true), OverallState::Degraded);
    }

    #[test]
    fn never_connected_live_source_is_unhealthy() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.source = SourceState::LndRest { connected: false };
        assert_eq!(assess(&s, &policy, now, true), OverallState::Unhealthy);
    }
}
