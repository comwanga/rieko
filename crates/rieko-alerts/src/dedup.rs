use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::sink::{Alert, AlertError, AlertSink};
use crate::state::{AlertState, AlertStateStore, DeliveryOutcome, DeliveryStatus};

/// A sink wrapper that suppresses repeats of the same alert within a cooldown,
/// with the cooldown and last-seen severity persisted across restarts.
///
/// This is the D9 alert-fatigue guard. It persists per-key state through an
/// [`AlertStateStore`] so a process restart (or crash) cannot reset the
/// cooldown or re-send at a stale severity. Time is compared via persisted UTC
/// timestamps, not `Instant`, so it holds across restart (D9, invariant #7).
///
/// Behavior:
/// * A successful delivery records `last_sent_at`/`last_severity` (UTC).
/// * The same key inside the cooldown window is suppressed unless the severity
///   escalated.
/// * A failed delivery records the failure but **not** `last_sent_at`, so it
///   never consumes the cooldown.
pub struct PersistentDedupingSink<S> {
    inner: S,
    store: Box<dyn AlertStateStore>,
    cooldown: Duration,
    sink_id: String,
    sent_count: u64,
    clock: Box<dyn Fn() -> DateTime<Utc>>,
}

impl<S> PersistentDedupingSink<S> {
    pub fn new(inner: S, store: Box<dyn AlertStateStore>, cooldown: Duration) -> Self {
        Self {
            inner,
            store,
            cooldown,
            sink_id: String::new(),
            sent_count: 0,
            clock: Box::new(Utc::now),
        }
    }

    /// Namespace the persisted state by destination (e.g. `"telegram"`).
    pub fn with_sink_id(mut self, id: impl Into<String>) -> Self {
        self.sink_id = id.into();
        self
    }

    /// Override the clock (used by tests to advance time deterministically).
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> DateTime<Utc>>) -> Self {
        self.clock = clock;
        self
    }

    pub fn sent_count(&self) -> u64 {
        self.sent_count
    }

    fn key(&self, alert: &Alert) -> String {
        if self.sink_id.is_empty() {
            alert.dedup_key.clone()
        } else {
            format!("{}|{}", self.sink_id, alert.dedup_key)
        }
    }
}

impl<S: AlertSink> AlertSink for PersistentDedupingSink<S> {
    fn send(&mut self, alert: &Alert) -> Result<DeliveryOutcome, AlertError> {
        let key = self.key(alert);
        let now = (self.clock)();
        let stored = self.store.read(&key)?.unwrap_or(AlertState::never());
        let in_cooldown = stored
            .last_sent_at
            .map(|t| now - t < chrono::Duration::from_std(self.cooldown).unwrap_or_default())
            .unwrap_or(false);
        let escalated = stored
            .last_severity
            .map(|s| alert.severity > s)
            .unwrap_or(false);

        if in_cooldown && !escalated {
            self.store.write(
                &key,
                &AlertState {
                    last_status: DeliveryStatus::Skipped,
                    ..stored
                },
            )?;
            return Ok(DeliveryOutcome::Suppressed);
        }

        match self.inner.send(alert) {
            Ok(inner_outcome) => {
                self.store.write(
                    &key,
                    &AlertState {
                        last_sent_at: Some(now),
                        last_severity: Some(alert.severity),
                        last_status: DeliveryStatus::Success,
                    },
                )?;
                self.sent_count += 1;
                Ok(inner_outcome)
            }
            Err(e) => {
                self.store.write(
                    &key,
                    &AlertState {
                        last_status: DeliveryStatus::Failed,
                        ..stored
                    },
                )?;
                Err(e)
            }
        }
    }
}

/// In-memory dedup guard for the one-shot `scan` path, kept for parity with the
/// previous behavior. The monitor uses [`PersistentDedupingSink`] instead.
pub struct DedupingSink<S> {
    inner: S,
    cooldown: Duration,
    last_sent: HashMap<String, Instant>,
    sent_count: u64,
}

impl<S> DedupingSink<S> {
    pub fn new(inner: S, cooldown: Duration) -> Self {
        Self {
            inner,
            cooldown,
            last_sent: HashMap::new(),
            sent_count: 0,
        }
    }

    pub fn sent_count(&self) -> u64 {
        self.sent_count
    }
}

impl<S: AlertSink> AlertSink for DedupingSink<S> {
    fn send(&mut self, alert: &Alert) -> Result<DeliveryOutcome, AlertError> {
        if let Some(last) = self.last_sent.get(&alert.dedup_key) {
            if last.elapsed() < self.cooldown {
                return Ok(DeliveryOutcome::Suppressed);
            }
        }
        self.inner.send(alert)?;
        self.last_sent
            .insert(alert.dedup_key.clone(), Instant::now());
        self.sent_count += 1;
        Ok(DeliveryOutcome::Delivered)
    }
}

/// Alias matching the ADR terminology for the persistent variant.
pub type PersistentAlertCooldown<S> = PersistentDedupingSink<S>;
/// Alias matching the ADR terminology for the in-memory variant.
pub type AlertCooldown<S> = DedupingSink<S>;

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use super::*;

    struct RecordingSink {
        sent: RefCell<Vec<String>>,
    }

    impl AlertSink for RecordingSink {
        fn send(&mut self, alert: &Alert) -> Result<DeliveryOutcome, AlertError> {
            self.sent.borrow_mut().push(alert.dedup_key.clone());
            Ok(DeliveryOutcome::Delivered)
        }
    }

    #[derive(Clone, Default)]
    struct MemoryStore(Rc<RefCell<HashMap<String, AlertState>>>);

    impl AlertStateStore for MemoryStore {
        fn read(&self, key: &str) -> Result<Option<AlertState>, AlertError> {
            Ok(self.0.borrow().get(key).copied())
        }
        fn write(&mut self, key: &str, state: &AlertState) -> Result<(), AlertError> {
            self.0.borrow_mut().insert(key.to_string(), *state);
            Ok(())
        }
    }

    fn alert(key: &str, severity: rieko_findings::Severity) -> Alert {
        Alert {
            dedup_key: key.into(),
            severity,
            title: "t".into(),
            message: "m".into(),
            timestamp: Utc::now(),
        }
    }

    type Clock = (Rc<RefCell<DateTime<Utc>>>, Box<dyn Fn() -> DateTime<Utc>>);

    /// A controllable clock backed by a cell we can mutate.
    fn clock() -> Clock {
        let cell = Rc::new(RefCell::new(Utc::now()));
        let c = cell.clone();
        let f: Box<dyn Fn() -> DateTime<Utc>> = Box::new(move || *c.borrow());
        (cell, f)
    }

    #[test]
    fn sends_first_alert_and_persists_success() {
        let store = MemoryStore::default();
        let mut sink = PersistentDedupingSink::new(
            RecordingSink {
                sent: RefCell::new(Vec::new()),
            },
            Box::new(store),
            Duration::from_secs(60),
        );
        sink.send(&alert("a|1", rieko_findings::Severity::Warning))
            .unwrap();
        assert_eq!(sink.sent_count(), 1);
    }

    #[test]
    fn suppresses_inside_cooldown_across_sink_recreation() {
        let store = MemoryStore::default();
        let (cell, clock) = clock();

        // First process: deliver once.
        {
            let mut sink = PersistentDedupingSink::new(
                RecordingSink {
                    sent: RefCell::new(Vec::new()),
                },
                Box::new(store.clone()),
                Duration::from_secs(60),
            )
            .with_clock(clock);
            sink.send(&alert("a|1", rieko_findings::Severity::Warning))
                .unwrap();
        }
        assert_eq!(store.0.borrow().len(), 1);

        // "Restart": a fresh sink reads the same store. Still inside cooldown
        // (we did not advance the clock), so it must be suppressed.
        let mut restarted = PersistentDedupingSink::new(
            RecordingSink {
                sent: RefCell::new(Vec::new()),
            },
            Box::new(store.clone()),
            Duration::from_secs(60),
        )
        .with_clock(Box::new(move || *cell.borrow()));
        restarted
            .send(&alert("a|1", rieko_findings::Severity::Warning))
            .unwrap();
        assert_eq!(restarted.sent_count(), 0, "cooldown must survive restart");
    }

    #[test]
    fn re_alerts_after_cooldown_elapses() {
        let store = MemoryStore::default();
        let (cell, clock) = clock();
        let mut sink = PersistentDedupingSink::new(
            RecordingSink {
                sent: RefCell::new(Vec::new()),
            },
            Box::new(store),
            Duration::from_secs(60),
        )
        .with_clock(clock);
        sink.send(&alert("a|1", rieko_findings::Severity::Warning))
            .unwrap();

        *cell.borrow_mut() += chrono::Duration::seconds(61);
        sink.send(&alert("a|1", rieko_findings::Severity::Warning))
            .unwrap();
        assert_eq!(sink.sent_count(), 2);
    }

    #[test]
    fn severity_increase_escalates_immediately() {
        let store = MemoryStore::default();
        let (cell, clock) = clock();
        let mut sink = PersistentDedupingSink::new(
            RecordingSink {
                sent: RefCell::new(Vec::new()),
            },
            Box::new(store),
            Duration::from_secs(60),
        )
        .with_clock(clock);
        sink.send(&alert("a|1", rieko_findings::Severity::Warning))
            .unwrap();
        // Inside cooldown, but severity went up -> deliver immediately.
        sink.send(&alert("a|1", rieko_findings::Severity::Critical))
            .unwrap();
        assert_eq!(sink.sent_count(), 2);
        // No clock advance happened.
        assert!(*cell.borrow() > Utc::now() - chrono::Duration::minutes(5));
    }

    #[test]
    fn failed_delivery_does_not_consume_cooldown() {
        struct FailingSink;
        impl AlertSink for FailingSink {
            fn send(&mut self, _: &Alert) -> Result<DeliveryOutcome, AlertError> {
                Err(AlertError::Sink("nope".into()))
            }
        }
        let store = MemoryStore::default();
        let (_cell, clock) = clock();
        let mut sink = PersistentDedupingSink::new(
            FailingSink,
            Box::new(store.clone()),
            Duration::from_secs(60),
        )
        .with_clock(clock);
        assert!(sink
            .send(&alert("a|1", rieko_findings::Severity::Warning))
            .is_err());
        // The store must NOT have last_sent_at set: cooldown not consumed.
        let state = store.0.borrow();
        let stored = state.get("a|1").copied().unwrap_or_else(AlertState::never);
        assert_eq!(
            stored.last_sent_at, None,
            "failed send must not record last_sent_at"
        );
    }

    #[test]
    fn in_memory_sink_still_deduplicates() {
        let inner = RecordingSink {
            sent: RefCell::new(Vec::new()),
        };
        let mut sink = DedupingSink::new(inner, Duration::from_secs(60));
        let outcome = sink
            .send(&alert("a|1", rieko_findings::Severity::Warning))
            .unwrap();
        assert_eq!(outcome, DeliveryOutcome::Delivered);
        let outcome = sink
            .send(&alert("a|1", rieko_findings::Severity::Warning))
            .unwrap();
        assert_eq!(outcome, DeliveryOutcome::Suppressed);
        assert_eq!(sink.sent_count(), 1);
    }

    #[test]
    fn persistent_failed_delivery_persists_failed_status() {
        struct FailingSink;
        impl AlertSink for FailingSink {
            fn send(&mut self, _: &Alert) -> Result<DeliveryOutcome, AlertError> {
                Err(AlertError::Sink("nope".into()))
            }
        }
        let store = MemoryStore::default();
        let (_cell, clock) = clock();
        let mut sink = PersistentDedupingSink::new(
            FailingSink,
            Box::new(store.clone()),
            Duration::from_secs(60),
        )
        .with_clock(clock);
        assert!(sink
            .send(&alert("a|1", rieko_findings::Severity::Warning))
            .is_err());
        let stored = store.0.borrow();
        let state = stored.get("a|1").copied().unwrap_or_else(AlertState::never);
        assert_eq!(
            state.last_status,
            DeliveryStatus::Failed,
            "failed delivery must persist Failed status"
        );
        assert_eq!(state.last_sent_at, None);
    }

    #[test]
    fn suppressed_send_does_not_increment_sent_count() {
        let store = MemoryStore::default();
        let (_cell, clock) = clock();
        let mut sink = PersistentDedupingSink::new(
            RecordingSink {
                sent: RefCell::new(Vec::new()),
            },
            Box::new(store),
            Duration::from_secs(60),
        )
        .with_clock(clock);
        sink.send(&alert("a|1", rieko_findings::Severity::Warning))
            .unwrap();
        assert_eq!(sink.sent_count(), 1);
        let outcome = sink
            .send(&alert("a|1", rieko_findings::Severity::Warning))
            .unwrap();
        assert_eq!(
            outcome,
            DeliveryOutcome::Suppressed,
            "cooldown skip must return Suppressed"
        );
        assert_eq!(
            sink.sent_count(),
            1,
            "sent_count must not increase on suppression"
        );
    }
}
