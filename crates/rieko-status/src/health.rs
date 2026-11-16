use chrono::{DateTime, Duration, Utc};

use crate::state::{ComponentState, OperationalState, OverallState};

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

/// Observation intervals that must pass without a finding being re-confirmed
/// before it is called stale. Two is the smallest allowance that guarantees a
/// scheduled observation was missed rather than not yet due. A heuristic.
pub const OBSERVATION_INTERVALS_BEFORE_STALE: i32 = 2;

impl HealthPolicy {
    /// How long an active finding may go without being re-confirmed before it
    /// is marked stale when read.
    ///
    /// The freshness threshold is the minimum. When the process serving the
    /// finding knows the longest interval at which it observes its sources,
    /// the threshold grows to cover that cadence, so a finding is not called
    /// stale while its next observation is not yet due. With no known interval
    /// (a one-shot scan, or findings written by another process) the minimum
    /// applies.
    pub fn finding_stale_after(&self, longest_observation_interval: Option<Duration>) -> Duration {
        match longest_observation_interval {
            // Saturate: chrono panics on `*` overflow, and its `checked_mul`
            // can return a value beyond `Duration::MAX`.
            Some(interval) => self.freshness.max(
                interval
                    .checked_mul(OBSERVATION_INTERVALS_BEFORE_STALE)
                    .map_or(Duration::MAX, |allowed| allowed.min(Duration::MAX)),
            ),
            None => self.freshness,
        }
    }
}

/// Exact health semantics (RIEKO-AUDIT-008).
///
/// * **NotInitialized**: no source has ever been read successfully.
/// * **Unhealthy**: the database failed its integrity check, or a live source
///   (BTCPay, LND, or directly polled Bitcoin Core or Lightning) was configured
///   but has never connected.
/// * **Degraded**:
///   * the latest ingestion attempt failed while valid older data exists;
///   * a previously successful live source, including directly polled Bitcoin
///     Core or Lightning, is currently disconnected;
///   * the latest detector-cycle attempt did not complete;
///   * source data is older than the freshness threshold;
///   * an LLM is configured but unverified or failing (explanations expected);
///   * an alert sink is configured but failing;
///   * the retention cleanup is failing (storage grows unbounded).
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

    // Bitcoin Core and Lightning are polled independently of `source`. Each is
    // present only once the agent has attempted to poll it.
    let polled = [
        state
            .bitcoin_core
            .as_ref()
            .map(|core| (core.connected, core.last_success)),
        state
            .lightning
            .as_ref()
            .map(|lightning| (lightning.connected, lightning.last_success)),
    ];
    let polled = || polled.iter().flatten();

    // A configured live source that has never connected is not operating at
    // all, rather than not-yet-used.
    if (state.last_ingestion_success.is_none() && !state.source.connected())
        || polled().any(|(connected, last_success)| !connected && last_success.is_none())
    {
        return OverallState::Unhealthy;
    }

    // Any source's first success initializes the pipeline.
    if state.last_ingestion_success.is_none()
        && polled().all(|(_, last_success)| last_success.is_none())
    {
        return OverallState::NotInitialized;
    }

    let mut degraded = false;

    // Latest attempt failed but recent valid data exists.
    if let (Some(attempt), Some(last_success)) =
        (state.last_ingestion_attempt, state.last_ingestion_success)
    {
        if attempt > last_success {
            degraded = true;
        }
    }

    // A live source that worked before is temporarily unavailable. A source
    // that has never connected is handled as Unhealthy above.
    if !state.source.connected() || polled().any(|(connected, _)| !connected) {
        degraded = true;
    }

    // An attempted cycle without a matching or newer success did not complete.
    if let Some(attempt) = state.last_cycle_attempt {
        if state
            .last_cycle_success
            .is_none_or(|success| attempt > success)
        {
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
    if matches!(
        state.llm,
        ComponentState::Configured | ComponentState::Failing
    ) || state.alert_sink == ComponentState::Failing
        || state.cleanup == ComponentState::Failing
    {
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
    fn configured_llm_not_yet_verified_is_degraded() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.last_ingestion_success = Some(now - Duration::seconds(10));
        s.source_data_at = Some(now - Duration::seconds(5));
        s.llm = ComponentState::Configured;
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
    fn failing_cleanup_is_degraded() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.last_ingestion_success = Some(now - Duration::seconds(10));
        s.source_data_at = Some(now - Duration::seconds(5));
        s.cleanup = ComponentState::Failing;
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

    #[test]
    fn disconnected_previously_successful_live_source_is_degraded() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.source = SourceState::LndRest { connected: false };
        s.last_ingestion_success = Some(now - Duration::minutes(1));
        s.source_data_at = Some(now - Duration::minutes(1));
        assert_eq!(assess(&s, &policy, now, true), OverallState::Degraded);
    }

    #[test]
    fn disconnected_btcpay_source_uses_live_source_health_semantics() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut never_connected = base();
        never_connected.source = SourceState::BtcPayGreenfield { connected: false };
        assert_eq!(
            assess(&never_connected, &policy, now, true),
            OverallState::Unhealthy
        );

        never_connected.last_ingestion_success = Some(now - Duration::minutes(1));
        never_connected.source_data_at = Some(now - Duration::minutes(1));
        assert_eq!(
            assess(&never_connected, &policy, now, true),
            OverallState::Degraded
        );
    }

    fn core(connected: bool, last_success: Option<DateTime<Utc>>) -> crate::BitcoinCoreState {
        crate::BitcoinCoreState {
            connected,
            consecutive_failures: u32::from(!connected),
            last_attempt: Utc::now(),
            last_success,
            snapshot: None,
        }
    }

    fn lightning(connected: bool, last_success: Option<DateTime<Utc>>) -> crate::LightningState {
        crate::LightningState {
            connected,
            consecutive_failures: u32::from(!connected),
            last_attempt: Utc::now(),
            last_success,
            snapshot: None,
        }
    }

    fn healthy_btcpay(now: DateTime<Utc>) -> OperationalState {
        let mut s = base();
        s.source = SourceState::BtcPayGreenfield { connected: true };
        s.last_ingestion_attempt = Some(now - Duration::seconds(10));
        s.last_ingestion_success = Some(now - Duration::seconds(10));
        s.source_data_at = Some(now - Duration::seconds(10));
        s
    }

    #[test]
    fn core_and_lightning_without_btcpay_are_healthy_after_their_first_success() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.bitcoin_core = Some(core(true, Some(now - Duration::seconds(10))));
        s.lightning = Some(lightning(true, Some(now - Duration::seconds(10))));
        assert_eq!(assess(&s, &policy, now, true), OverallState::Healthy);

        let mut core_only = base();
        core_only.bitcoin_core = Some(core(true, Some(now - Duration::seconds(10))));
        assert_eq!(
            assess(&core_only, &policy, now, true),
            OverallState::Healthy
        );

        let mut lightning_only = base();
        lightning_only.lightning = Some(lightning(true, Some(now - Duration::seconds(10))));
        assert_eq!(
            assess(&lightning_only, &policy, now, true),
            OverallState::Healthy
        );
    }

    #[test]
    fn disconnected_core_or_lightning_after_a_success_is_degraded() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let earlier = Some(now - Duration::minutes(5));

        let mut core_down = healthy_btcpay(now);
        core_down.bitcoin_core = Some(core(false, earlier));
        assert_eq!(
            assess(&core_down, &policy, now, true),
            OverallState::Degraded
        );

        let mut lightning_down = healthy_btcpay(now);
        lightning_down.lightning = Some(lightning(false, earlier));
        assert_eq!(
            assess(&lightning_down, &policy, now, true),
            OverallState::Degraded
        );

        let mut both_down_without_btcpay = base();
        both_down_without_btcpay.bitcoin_core = Some(core(false, earlier));
        both_down_without_btcpay.lightning = Some(lightning(false, earlier));
        assert_eq!(
            assess(&both_down_without_btcpay, &policy, now, true),
            OverallState::Degraded
        );
    }

    #[test]
    fn never_connected_core_or_lightning_is_unhealthy() {
        let policy = HealthPolicy::default();
        let now = Utc::now();

        let mut core_never = healthy_btcpay(now);
        core_never.bitcoin_core = Some(core(false, None));
        assert_eq!(
            assess(&core_never, &policy, now, true),
            OverallState::Unhealthy
        );

        let mut lightning_never = base();
        lightning_never.lightning = Some(lightning(false, None));
        assert_eq!(
            assess(&lightning_never, &policy, now, true),
            OverallState::Unhealthy
        );
    }

    #[test]
    fn connected_core_and_lightning_do_not_change_a_healthy_btcpay_verdict() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = healthy_btcpay(now);
        s.bitcoin_core = Some(core(true, Some(now - Duration::seconds(10))));
        s.lightning = Some(lightning(true, Some(now - Duration::seconds(10))));
        assert_eq!(assess(&s, &policy, now, true), OverallState::Healthy);
    }

    #[test]
    fn finding_stale_threshold_is_the_freshness_minimum_without_a_known_interval() {
        let policy = HealthPolicy::default();
        assert_eq!(policy.finding_stale_after(None), Duration::hours(2));
    }

    #[test]
    fn finding_stale_threshold_keeps_the_minimum_for_short_intervals() {
        let policy = HealthPolicy::default();
        for seconds in [1, 60, 3_599, 3_600] {
            assert_eq!(
                policy.finding_stale_after(Some(Duration::seconds(seconds))),
                Duration::hours(2),
                "{seconds}s"
            );
        }
    }

    #[test]
    fn finding_stale_threshold_allows_two_intervals_once_that_exceeds_the_minimum() {
        let policy = HealthPolicy::default();
        assert_eq!(
            policy.finding_stale_after(Some(Duration::seconds(3_601))),
            Duration::seconds(7_202)
        );
        assert_eq!(
            policy.finding_stale_after(Some(Duration::hours(6))),
            Duration::hours(12)
        );
        // The longest interval the agent accepts.
        assert_eq!(
            policy.finding_stale_after(Some(Duration::seconds(86_400))),
            Duration::hours(48)
        );
    }

    #[test]
    fn finding_stale_threshold_saturates_instead_of_overflowing() {
        let policy = HealthPolicy::default();
        assert_eq!(
            policy.finding_stale_after(Some(Duration::MAX)),
            Duration::MAX
        );
    }

    #[test]
    fn incomplete_cycle_is_degraded() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.last_ingestion_success = Some(now - Duration::minutes(1));
        s.source_data_at = Some(now - Duration::minutes(1));
        s.last_cycle_attempt = Some(now - Duration::seconds(30));
        assert_eq!(assess(&s, &policy, now, true), OverallState::Degraded);
    }

    #[test]
    fn latest_failed_cycle_is_degraded() {
        let policy = HealthPolicy::default();
        let now = Utc::now();
        let mut s = base();
        s.last_ingestion_success = Some(now - Duration::minutes(1));
        s.source_data_at = Some(now - Duration::minutes(1));
        s.last_cycle_success = Some(now - Duration::seconds(45));
        s.last_cycle_attempt = Some(now - Duration::seconds(30));
        assert_eq!(assess(&s, &policy, now, true), OverallState::Degraded);
    }
}
