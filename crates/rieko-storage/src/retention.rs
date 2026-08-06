use std::time::Duration;

/// A simple, configurable retention policy for bounded snapshot growth
/// (RIEKO-AUDIT-016). The default keeps history long enough for the drift
/// detector while guaranteeing an upper bound on storage growth. There is no
/// separate analytics database: retention applies to the existing SQLite table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Snapshots older than this are removed. Default: 30 days.
    pub snapshot_max_age: Duration,
    /// Snapshots of closed/terminated channels older than this are removed.
    /// Closed channels are gone and cannot be monitored, so their history is
    /// kept for a much shorter grace period. Default: 3 days.
    pub closed_channel_max_age: Duration,
    /// Optional cap on snapshots kept per channel (newest wins). When `None`,
    /// time-based retention alone bounds growth. Default: `None`.
    pub max_snapshots_per_channel: Option<usize>,
    /// Optional absolute cap on total snapshot rows (newest wins). When `None`,
    /// time-based retention alone bounds growth. Default: `None`.
    pub max_total_snapshots: Option<usize>,
    /// How often the monitor runs a cleanup pass, regardless of cycle rate.
    /// Default: 6 hours.
    pub cleanup_interval: Duration,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            snapshot_max_age: Duration::from_secs(30 * 24 * 3600),
            closed_channel_max_age: Duration::from_secs(3 * 24 * 3600),
            max_snapshots_per_channel: None,
            max_total_snapshots: None,
            cleanup_interval: Duration::from_secs(6 * 3600),
        }
    }
}

impl RetentionPolicy {
    /// Upper bound on how old a snapshot may be, per status. Active (open)
    /// channels keep at least `snapshot_max_age`; closed/terminated channels
    /// expire after the shorter `closed_channel_max_age`.
    pub fn max_age_for_status(&self, status: rieko_domain::ChannelStatus) -> Duration {
        if status.is_closed() {
            self.closed_channel_max_age
        } else {
            self.snapshot_max_age
        }
    }
}

/// Outcome of one cleanup pass, for observability (status/CLI/logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneSummary {
    /// Snapshots removed from `channel_snapshots`.
    pub deleted_snapshots: usize,
    /// Whether every part of the pass ran (age, per-channel cap, total cap).
    pub complete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rieko_domain::ChannelStatus;

    #[test]
    fn closed_channels_expire_sooner() {
        let p = RetentionPolicy::default();
        assert!(p.max_age_for_status(ChannelStatus::Active) == p.snapshot_max_age);
        assert!(p.max_age_for_status(ChannelStatus::Closed) == p.closed_channel_max_age);
        assert!(p.closed_channel_max_age < p.snapshot_max_age);
    }

    #[test]
    fn defaults_form_a_documented_upper_bound() {
        let p = RetentionPolicy::default();
        assert!(p.snapshot_max_age >= Duration::from_secs(24 * 3600));
        assert!(p.closed_channel_max_age < p.snapshot_max_age);
        assert!(p.cleanup_interval > Duration::ZERO);
    }
}
